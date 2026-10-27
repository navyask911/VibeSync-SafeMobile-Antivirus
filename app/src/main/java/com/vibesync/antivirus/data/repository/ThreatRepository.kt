package com.vibesync.antivirus.data.repository
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.engine.YaraRuleImportStore
import com.vibesync.antivirus.core.hashdb.HashDatabaseManager
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability
import com.vibesync.antivirus.core.worker.HashDatabaseSyncScheduler
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import androidx.documentfile.provider.DocumentFile
import androidx.room.withTransaction
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.quarantine.LocalQuarantineManager
import com.vibesync.antivirus.core.quarantine.QuarantineDeleteOperation
import com.vibesync.antivirus.core.quarantine.QuarantineDeleteOutcome
import com.vibesync.antivirus.core.quarantine.QuarantineOutcome
import com.vibesync.antivirus.core.worker.LocalDefinitionLoader
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import com.vibesync.antivirus.core.worker.ThreatFeedSyncScheduler
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.flowOn
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import com.vibesync.antivirus.core.security.TrustedAppStore
import com.vibesync.antivirus.core.engine.InstalledAppItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.IOException
import java.util.UUID

class ThreatRepository(
 private val context: Context,
 private val database: ThreatDatabase,
 private val scanner: PackageScanner,
 private val definitionLoader: LocalDefinitionLoader,
 private val threatIntelligence: ThreatIntelligenceRepository,
 private val hashDatabaseManager: HashDatabaseManager? = null
) {
 private val privateTextStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { EncryptedHashStore(context) }
 private val maxSafScanFiles = 10_000
 private val trustedAppStore = TrustedAppStore(context)
 suspend fun installedAppInventory(): List<InstalledAppItem> = withContext(Dispatchers.IO) {
  scanner.installedAppInventory()
 }
 suspend fun trustApp(result: ScanResult): Boolean {
  val name = result.packageName ?: return false
  if (!isEligibleInstalledApp(name)) return false
  return trustedAppStore.trust(name)
 }

 fun currentHashDatabaseCapability() = hashDatabaseManager?.capability
 suspend fun securityAssessment() = withContext(Dispatchers.IO) {
  if (!context.getSharedPreferences(com.vibesync.antivirus.SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
      .getBoolean(com.vibesync.antivirus.SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)) {
   return@withContext com.vibesync.antivirus.core.security.DeviceSecurityScore.evaluate(
    com.vibesync.antivirus.core.security.DeviceSecuritySignals(), System.currentTimeMillis())
  }
  val active = hashDatabaseManager?.capability
  val updatedAt = if (active?.enabled == true)
   com.vibesync.antivirus.core.hashdb.HashDatabaseFreshness.updatedAt(context, active.version) else null
  com.vibesync.antivirus.core.security.DeviceSecurityScore.evaluate(
   com.vibesync.antivirus.core.security.DeviceSecurityInspector.inspect(context, updatedAt), System.currentTimeMillis())
 }
 fun reportPlayProtect(enabled: Boolean) = com.vibesync.antivirus.core.security.DeviceSecurityInspector.reportPlayProtect(context, enabled)
 fun loadScanSummary(): com.vibesync.antivirus.core.engine.ScanCompletionSummary? = runCatching {
  val p = context.getSharedPreferences("safe_mobile_last_scan", Context.MODE_PRIVATE)
  val time = p.getLong("completed_at", 0L)
  if (time <= 0L) null else com.vibesync.antivirus.core.engine.ScanCompletionSummary(
   p.getInt("apps", 0), p.getInt("files", 0), p.getInt("threats", 0), p.getInt("review", 0), p.getInt("unreadable", 0), time, p.getBoolean("signed_definitions_used", false))
 }.getOrNull()
 fun saveScanSummary(summary: com.vibesync.antivirus.core.engine.ScanCompletionSummary) {
  context.getSharedPreferences("safe_mobile_last_scan", Context.MODE_PRIVATE).edit()
   .putInt("apps", summary.appCount).putInt("files", summary.fileCount).putInt("threats", summary.threats)
   .putInt("review", summary.review).putInt("unreadable", summary.unreadable).putLong("completed_at", summary.completedAt).putBoolean("signed_definitions_used", summary.signedDefinitionsUsed).apply()
 }

 fun observeRecentAudits(): Flow<List<ScanAudit>> =
  database.threatDao().observeRecentAudits().map { rows ->
   rows.map { row -> row.copy(packageOrPath = revealPrivateTextSafely(row.packageOrPath, "scan-label")) }
  }

 fun observeRecentSecurityIncidents() =
  database.securityIncidentDao().observeRecent(100).map { rows ->
   rows.map { row ->
    row.copy(
     installerPackage = row.installerPackage?.let { revealPrivateTextSafely(it, "incident-installer") },
     sourcePackage = row.sourcePackage?.let { revealPrivateTextSafely(it, "incident-source") },
     filename = row.filename?.let { revealPrivateTextSafely(it, "incident-filename") },
     originalPath = row.originalPath?.let { revealPrivateTextSafely(it, "incident-path") },
     reason = revealPrivateTextSafely(row.reason, "incident-reason")
    )
   }.filter { row ->
    row.eventKind !in setOf("PACKAGE_INSTALL", "PACKAGE_UPDATED") ||
     row.sourcePackage?.let(::isEligibleInstalledApp) == true
   }
  }.flowOn(Dispatchers.IO)

 /** Raw downloaded files have no installed-package identity and keep exact-hash detection. */
 suspend fun isReviewableResult(result: ScanResult): Boolean = withContext(Dispatchers.IO) {
  result.packageName?.let(::isEligibleInstalledApp) ?: true
 }

 private fun isEligibleInstalledApp(name: String): Boolean =
  TrustedPackageWhitelist.isEligibleForReview(context, name)

 private fun revealPrivateTextSafely(value: String, purpose: String): String =
  runCatching { privateTextStore.revealPrivateText(value, purpose) }
   .getOrDefault("[Encrypted local metadata unavailable]")
 fun observeActiveThreatIndicatorCount(): Flow<Int> = threatIntelligence.observeActiveIndicatorCount()
 fun observeLastSuccessfulThreatFeedSyncAt(): Flow<Long?> = threatIntelligence.observeLastSuccessfulSyncAt()
 fun observeLatestThreatFeedSyncState(): Flow<ThreatFeedSyncStateEntity?> = threatIntelligence.observeLatestSyncState()
 fun requestThreatFeedSync() = ThreatFeedSyncScheduler.enqueueNow(context)
 suspend fun lookupThreatHash(sha256: String?, md5: String?) = threatIntelligence.lookupHash(sha256, md5)
 suspend fun lookupNetworkIoc(value: String) = threatIntelligence.lookupIoc(value)
 suspend fun lookupDomain(domain: String) = threatIntelligence.lookupDomain(domain)
 suspend fun lookupIpAddress(ipAddress: String) = threatIntelligence.lookupIpAddress(ipAddress)
 suspend fun getActiveThreatIndicatorCount(): Int = threatIntelligence.getActiveSignatureCount()
 fun observeActiveSignatureCount(): Flow<Int> = threatIntelligence.observeActiveSignatureCount()
 fun observeLastSuccessfulThreatFeedSyncTime(): Flow<Long?> = threatIntelligence.observeLastSuccessfulSyncTime()
 fun syncThreatFeeds() = requestThreatFeedSync()
 suspend fun scanInstalledApps(progress: suspend (Int, Int) -> Unit = { _, _ -> }): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanInstalledApps(progress)
 }

 /** Scan installed APKs and files in the user's persisted SAF folder, with bounded traversal. */
 suspend fun scanFull(progress: suspend (Int, Int) -> Unit = { _, _ -> }): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  var fileCount = 0
  for (ignored in selectedFolderFiles()) {
   currentCoroutineContext().ensureActive()
   if (fileCount < maxSafScanFiles) fileCount++
  }
  var installedCount = 0
  val installedResults = scanner.scanInstalledApps { processed, total ->
   installedCount = total
   progress(processed, (total.toLong() + fileCount).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
  }
  val findings = ArrayList<ScanResult>()
  var filesProcessed = 0
  for (candidate in selectedFolderFiles()) {
   currentCoroutineContext().ensureActive()
   val assessed = runCatching { context.contentResolver.openInputStream(candidate.uri) }.getOrNull()?.let { stream ->
    scanner.scanStream(candidate.displayName, stream, UUID.randomUUID().toString(), persistAudit = false)
   } ?: recordUnscannedUri(candidate.displayName, context.getString(R.string.file_stream_failed), UUID.randomUUID().toString())
   if (assessed.verdict != ScanVerdict.NO_MATCH) findings += assessed
   filesProcessed++
   progress((installedCount.toLong() + filesProcessed).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
    (installedCount.toLong() + fileCount).coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
  }
  val total = (installedCount.toLong() + fileCount).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
  progress(total, total)
  installedResults + findings
 }

 private data class SelectedFolderFile(val uri: Uri, val displayName: String)

 /**
  * Requires an explicitly persisted SAF grant, recurses at most 4 directory levels, and visits at
  * most 10,000 items per pass. It never probes or enumerates shared storage outside that grant.
  */
 private fun selectedFolderFiles(): Sequence<SelectedFolderFile> = sequence {
  var count = 0
  for (file in com.vibesync.antivirus.core.observer.SafTreeWalker.files(context,
      StorageAccessPreferences.accessibleTreeUris(context))) {
   if (++count > maxSafScanFiles) break
   yield(SelectedFolderFile(file.uri, file.name?.take(250) ?: context.getString(R.string.unknown_file)))
  }
 }

 private fun encryptPrivateText(value: String?, purpose: String): String? =
  value?.takeIf { it.isNotEmpty() }?.let { privateTextStore.protectPrivateText(it.take(1024), purpose) }

 private fun decryptPrivateText(value: String?, purpose: String): String? =
  value?.let { revealPrivateTextSafely(it, purpose) }

 suspend fun scanInstalledPackage(name: String): ScanResult? = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanInstalledPackage(name)
 }
 suspend fun scanFile(file: File): ScanResult = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanFile(file)
 }
 suspend fun scanUri(uri: Uri): ScanResult = withContext(Dispatchers.IO) {
  val quarantineManager = LocalQuarantineManager(context)
  val scanSessionId = UUID.randomUUID().toString()
  val label = runCatching {
   context.contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),null,null,null)?.use { c ->
    if (c.moveToFirst()) c.getString(0) else null
   }
  }.getOrNull() ?: uri.lastPathSegment ?: context.getString(R.string.unknown_file)
  if (!quarantineManager.supportsLocalUri(uri)) {
   return@withContext recordUnscannedUri(
    label,
    context.getString(R.string.local_files_only),
    scanSessionId
   )
  }
  definitionLoader.importBundledIfEmpty()
  val stream = runCatching { context.contentResolver.openInputStream(uri) }.getOrNull()
   ?: return@withContext recordUnscannedUri(
    label,
    context.getString(R.string.file_stream_failed),
    scanSessionId
   )
  scanner.scanStream(label, stream, scanSessionId).copy(sourceUri = uri.toString())
 }

 private suspend fun recordUnscannedUri(label: String, reason: String, scanSessionId: String): ScanResult {
  val now = System.currentTimeMillis()
  val result = ScanResult(
   packageOrPath = label,
   displayName = label,
   sha256 = null,
   md5 = null,
   verdict = ScanVerdict.NOT_SCANNED,
   reasons = listOf(reason),
   durationMs = 0L,
   scanSessionId = scanSessionId
  )
  runCatching {
   database.threatDao().insertAudit(
    ScanAudit(
     packageOrPath = privateTextStore.protectPrivateText(label.take(250), "scan-label"),
     hash = "",
     scanTimestamp = now,
     verdict = ScanVerdict.NOT_SCANNED.name,
     scanDuration = 0L,
     scanSessionId = scanSessionId
    )
   )
  }
  return result
 }
 suspend fun quarantineObservedDownload(uri: Uri, expectedSha256: String?): QuarantineOutcome = withContext(Dispatchers.IO) {
  LocalQuarantineManager(context).quarantine(uri, expectedSha256, removeOriginalAfterVerified = true)
 }
 suspend fun quarantineObservedDownload(file: File, expectedSha256: String?): QuarantineOutcome = withContext(Dispatchers.IO) {
  LocalQuarantineManager(context).quarantineFile(file, expectedSha256, removeOriginalAfterVerified = true)
 }
 suspend fun retryRemoveObservedDownload(uri: Uri): Boolean = withContext(Dispatchers.IO) {
  LocalQuarantineManager(context).retryRemoveOriginal(uri)
 }
 suspend fun retryRemoveObservedDownload(file: File): Boolean = withContext(Dispatchers.IO) {
  LocalQuarantineManager(context).retryRemoveOriginal(file)
 }
 suspend fun quarantineSelectedFile(uri: Uri, expectedSha256: String?): String = withContext(Dispatchers.IO) {
  val outcome = LocalQuarantineManager(context).quarantine(uri, expectedSha256, removeOriginalAfterVerified = false)
  if (outcome.originalRemoved) context.getString(R.string.quarantine_success_removed, outcome.privateCopy.name)
  else context.getString(R.string.quarantine_success_copy_only, outcome.privateCopy.name)
 }

 suspend fun listQuarantinedFiles(): List<File> = withContext(Dispatchers.IO) {
  LocalQuarantineManager(context).listQuarantinedFiles()
 }
 suspend fun restoreQuarantinedFile(file: File, destinationUri: Uri): String = withContext(Dispatchers.IO) {
  val manager = LocalQuarantineManager(context)
  val label = manager.displayName(file)
  val bytes = manager.restoreToUri(file, destinationUri)
  context.getString(R.string.quarantine_restore_success, label, bytes)
 }
 suspend fun deleteQuarantinedFile(file: File): String = withContext(Dispatchers.IO) {
  val manager = LocalQuarantineManager(context)
  val label = runCatching { manager.displayName(file) }.getOrDefault(file.name)
  val operation = QuarantineDeleteOperation(
   deletePayload = { candidate -> manager.deleteQuarantinedFile(candidate) },
   deleteRoomEntry = { vaultId ->
    database.withTransaction {
     database.quarantineVaultDao().deleteById(vaultId)
    }
   }
  )
  when (operation.delete(file)) {
   QuarantineDeleteOutcome.DELETED -> context.getString(R.string.quarantine_delete_success, label)
   QuarantineDeleteOutcome.FILE_NOT_FOUND -> throw java.io.FileNotFoundException("Quarantine file no longer exists.")
   QuarantineDeleteOutcome.ACCESS_DENIED -> throw SecurityException("Access to quarantine file was denied.")
   QuarantineDeleteOutcome.FAILED -> throw IOException("Could not permanently delete quarantined file.")
  }
 }

 suspend fun hashDatabaseCapability(): HashDatabaseCapability = hashDatabaseManager?.let { it.restoreActiveDatabase() }
  ?: HashDatabaseCapability(false, reason = "Disabled: hash database manager is unavailable.")

 suspend fun importSignedHashDatabase(uri: Uri): HashDatabaseCapability = withContext(Dispatchers.IO) {
  val manager = hashDatabaseManager ?: throw IllegalStateException("Signed hash database engine is unavailable.")
  val stream = context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  manager.importBundle(stream)
 }

 fun requestHashDatabaseSync() = HashDatabaseSyncScheduler.enqueueNow(context)

 suspend fun importPendingYaraRule(uri: Uri): String = withContext(Dispatchers.IO) {
  val stream = context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  val saved = YaraRuleImportStore(context).importPending(stream)
  "Stored ${saved.name} for review. YARA remains DISABLED; this file will not be executed."
 }

suspend fun importOfflineDefinitions(uri: Uri): String = withContext(Dispatchers.IO) {
  val stream=context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  context.getString(R.string.import_success,definitionLoader.importFromStream(stream))
 }
 suspend fun signatureCount(): Int = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  database.threatDao().countSignatures()
 }
 suspend fun deepScan(): List<ScanResult> = scanFull()
}

