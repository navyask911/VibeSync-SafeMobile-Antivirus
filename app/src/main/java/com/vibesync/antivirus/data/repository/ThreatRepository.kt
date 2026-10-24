package com.vibesync.antivirus.data.repository
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.PackageScanner
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
 private val threatIntelligence: ThreatIntelligenceRepository
) {
 private val privateTextStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { EncryptedHashStore(context) }
 private val maxSafScanFiles = 10_000
 private val maxSafDirectoryDepth = 4

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
   }
  }

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
  if (!StorageAccessPreferences.hasAccess(context)) return@sequence
  val treeUri = StorageAccessPreferences.selectedTreeUri(context) ?: return@sequence
  val root = runCatching { DocumentFile.fromTreeUri(context, treeUri) }.getOrNull() ?: return@sequence
  var visited = 0
  fun walk(directory: DocumentFile, depth: Int): Sequence<SelectedFolderFile> = sequence {
   val children = runCatching { directory.listFiles() }.getOrElse { emptyArray() }
   for (child in children) {
    if (visited >= maxSafScanFiles) break
    visited++
    val label = child.name?.take(250)?.ifBlank { null } ?: context.getString(R.string.unknown_file)
    if (child.isDirectory && depth < maxSafDirectoryDepth) {
     yieldAll(walk(child, depth + 1))
    } else if (child.isFile && child.canRead()) {
     yield(SelectedFolderFile(child.uri, label))
    }
   }
  }
  yieldAll(walk(root, 0))
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
