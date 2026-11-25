package com.vibesync.antivirus.data.repository
import android.content.Context
import android.net.Uri
import android.util.Log
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.UiText
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
import com.vibesync.antivirus.core.engine.ScanPublishStageException
import com.vibesync.antivirus.core.quarantine.LocalQuarantineManager
import com.vibesync.antivirus.core.quarantine.QuarantineDeleteOperation
import com.vibesync.antivirus.core.quarantine.QuarantineDeleteOutcome
import com.vibesync.antivirus.core.quarantine.QuarantineOutcome
import com.vibesync.antivirus.core.worker.LocalDefinitionLoader
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ScanSessionEntity
import com.vibesync.antivirus.data.local.ScanSessionState
import com.vibesync.antivirus.data.local.ScanSessionItemEntity
import com.vibesync.antivirus.data.local.ScanSessionCounts
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import com.vibesync.antivirus.core.worker.ThreatFeedSyncScheduler
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import com.vibesync.antivirus.data.local.AnalyticsWeek
import com.vibesync.antivirus.data.local.ScanAnalytics
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.flowOn
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import com.vibesync.antivirus.core.security.TrustedAppStore
import com.vibesync.antivirus.core.engine.InstalledAppItem
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.vibesync.antivirus.core.worker.withInstalledAppScanTimeout
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import java.io.File
import java.io.IOException
import java.util.UUID
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

data class ScanPublishSummary(val failureCount: Int, val totalPackages: Int)

/**
 * Shared policy for rows restored from Room into Scan & Lab and scan reports.
 * Package eligibility remains supplied by ThreatRepository so PackageManager,
 * protected-namespace and signer checks stay centralized at the repository boundary.
 */
internal object PersistedScanResultPolicy {
    fun packageNameFromPersistedRow(
        itemType: String,
        itemKey: String,
        storedPackageName: String?
    ): String? {
        if (!storedPackageName.isNullOrBlank()) return storedPackageName
        if (itemType != "app" || !itemKey.startsWith("app:")) return null
        return itemKey.removePrefix("app:").takeIf { it.isNotBlank() }
    }

    /** An app row without a recoverable package identity must never masquerade as a file row. */
    fun hasDisplayableIdentity(itemType: String, packageName: String?): Boolean =
        itemType != "app" || !packageName.isNullOrBlank()

    fun normalizeOfficialGoogleResult(
        result: ScanResult,
        signerVerified: Boolean
    ): ScanResult {
        val googleNamespace = result.packageName?.let {
            com.vibesync.antivirus.core.security.OfficialGoogleAppPolicy.isGooglePackageName(it)
        } == true
        if (!signerVerified || !googleNamespace) return result

        return result.copy(
            verdict = ScanVerdict.NO_MATCH,
            reasons = listOf("Official Google app verified by trusted signing certificate. Clean & Safe."),
            riskScore = 0f,
            riskReport = null,
            mlProbability = null,
            threatEventId = null,
            detectionSource = com.vibesync.antivirus.core.engine.DetectionSource.NONE,
            malwareName = null,
            yaraVerdict = null,
            confidence = 1f,
            scanSource = com.vibesync.antivirus.core.engine.ScanSource.GOOGLE_VERIFIED,
            analysisStages = listOf("SIGNER_VERIFIED", "VERDICT"),
            trustedByUser = false,
            reasonTexts = emptyList()
        )
    }

    suspend fun selectVisiblePersistedResults(
        results: List<ScanResult>,
        isReviewable: suspend (ScanResult) -> Boolean
    ): List<ScanResult> {
        val visible = ArrayList<ScanResult>(results.size)
        results.forEach { result ->
            // File/folder scan entries have no installed-package identity.
            if (result.packageName == null || isReviewable(result)) {
                visible += result
            }
        }
        return com.vibesync.antivirus.core.engine.ScanResultOrdering.sort(visible)
    }
}

private class ScanPublishCounters {
 val failureCount = AtomicInteger(0)
 val totalPackages = AtomicInteger(0)
}

class ThreatRepository(
 private val context: Context,
 private val database: ThreatDatabase,
 private val scanner: PackageScanner,
 private val definitionLoader: LocalDefinitionLoader,
 private val threatIntelligence: ThreatIntelligenceRepository,
 private val hashDatabaseManager: HashDatabaseManager? = null
) {
 private val privateTextStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { EncryptedHashStore(context) }
 private val maxSafScanFiles = 1_000
 private val trustedAppStore = TrustedAppStore(context)
 private val skippedSafFileCounts = ConcurrentHashMap<String, AtomicInteger>()
 private val scanPublishCounters = ConcurrentHashMap<String, ScanPublishCounters>()
 private val safInventorySnapshots = SafInventorySnapshotCache<SelectedFolderFile>()

 private fun recordSkippedSafFile(sessionId: String, uri: Uri, error: Exception) {
  Log.e("ScanDebug", "Skipping file: $uri", error)
  if (error is SecurityException || error is IllegalArgumentException) {
   skippedSafFileCounts.computeIfAbsent(sessionId) { AtomicInteger(0) }.incrementAndGet()
  }
 }

 fun skippedSafFileCount(sessionId: String): Int = skippedSafFileCounts[sessionId]?.get() ?: 0

 fun clearSkippedSafFileCount(sessionId: String) { skippedSafFileCounts.remove(sessionId) }

 fun scanPublishSummary(sessionId: String): ScanPublishSummary {
  val counters = scanPublishCounters[sessionId]
  return ScanPublishSummary(
   failureCount = counters?.failureCount?.get() ?: 0,
   totalPackages = counters?.totalPackages?.get() ?: 0
  )
 }

 fun clearScanPublishSummary(sessionId: String) {
  scanPublishCounters.remove(sessionId)
 }

 suspend fun clearScanSessionStateCheckpoints() = withContext(Dispatchers.IO) {
  database.withTransaction {
   val dao = database.threatDao()
   dao.clearAllSessions()
   // Once state rows are removed, any orphaned IN_PROGRESS session is no longer resumable.
   dao.markInProgressAsInterrupted()
  }
  safInventorySnapshots.clear()
 }

 private suspend fun scanSafFile(
  uri: Uri,
  fallbackName: String,
  scanSessionId: String
 ): ScanResult {
  val displayName = fallbackName.takeIf { it.isNotBlank() }?.take(250)
   ?: context.getString(R.string.unknown_file)
  return try {
   // Avoid optional DocumentsProvider metadata projections on OEM providers.
   // Read the granted document payload directly and scan the stream for hash/YARA.
   val stream = context.contentResolver.openInputStream(uri)
   if (stream == null) {
    Log.w("SafeMobileScan", "SAF provider returned no input stream for $uri")
    recordUnscannedUri(displayName, context.getString(R.string.file_stream_failed), scanSessionId)
   } else {
    stream.use {
     scanner.scanStream(displayName, it, scanSessionId, persistAudit = false)
      .copy(sourceUri = uri.toString())
    }
   }
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   Log.e("SafeMobileScan", "SAF file scan failed; continuing with the next document: $uri", error)
   recordSkippedSafFile(scanSessionId, uri, error)
   recordUnscannedUri(displayName, context.getString(R.string.file_stream_failed), scanSessionId)
  }
 }
 suspend fun installedAppInventory(): List<InstalledAppItem> = withContext(Dispatchers.IO) {
  scanner.installedAppInventory()
 }
 suspend fun trustApp(result: ScanResult): Boolean {
  val name = result.packageName ?: return false
  if (!isEligibleInstalledApp(name)) return false
  return trustedAppStore.trust(name)
 }

 suspend fun trustPackageName(packageName: String): Boolean = withContext(Dispatchers.IO) {
  if (!isEligibleInstalledApp(packageName)) return@withContext false
  trustedAppStore.trust(packageName)
 }

 suspend fun trustFileHash(sha256: String): Boolean = withContext(Dispatchers.IO) {
  val normalized = sha256.trim().lowercase()
  if (!normalized.matches(Regex("^[0-9a-f]{64}$"))) return@withContext false
  val prefs = context.getSharedPreferences(TRUSTED_FILE_HASHES_PREFS, Context.MODE_PRIVATE)
  val current = prefs.getStringSet(TRUSTED_FILE_HASHES_KEY, emptySet()).orEmpty()
  prefs.edit().putStringSet(TRUSTED_FILE_HASHES_KEY, current + normalized).commit()
 }

 private fun applyTrustedFileHash(result: ScanResult): ScanResult {
  val hash = result.sha256?.lowercase()?.takeIf { it.matches(Regex("^[0-9a-f]{64}$")) } ?: return result
  val trusted = context.getSharedPreferences(TRUSTED_FILE_HASHES_PREFS, Context.MODE_PRIVATE)
   .getStringSet(TRUSTED_FILE_HASHES_KEY, emptySet()).orEmpty().contains(hash)
  if (!trusted) return result
  return result.copy(
   verdict = ScanVerdict.NO_MATCH,
   riskScore = 0f,
   reasons = listOf("User-approved local file hash."),
   reasonTexts = emptyList(),
   riskReport = null,
   mlProbability = null,
   threatEventId = null,
   trustedByUser = true
  )
 }

 suspend fun removeTrust(packageName: String) {
  trustedAppStore.untrust(packageName)
 }
 suspend fun isTrusted(packageName: String): Boolean = trustedAppStore.isTrusted(packageName)

 suspend fun startScanSession(sessionId: String, scanType: String,
  operationType: String = scanType, sourceUri: String? = null, packageName: String? = null,
  isManual: Boolean = true) = withContext(Dispatchers.IO) {
  database.withTransaction {
   val dao = database.threatDao()
   val priorSession = dao.findScanSession(sessionId)
   dao.upsertScanSession(
    ScanSessionEntity(
     sessionId = sessionId,
     scanType = scanType,
     startedAt = priorSession?.startedAt ?: System.currentTimeMillis(),
     completedAt = null,
     status = ScanSessionEntity.IN_PROGRESS,
     elapsedMs = priorSession?.elapsedMs ?: 0L
    )
   )
   val existing = dao.findScanSessionState(sessionId)
   val normalized = if (scanType.equals("DEEP_SCAN", true) || scanType.equals("PERIODIC_DEEP_SCAN", true) || scanType.equals("SELECTED_FOLDER", true)) "deep" else "full"
   val encryptedUri = sourceUri?.let { privateTextStore.protectPrivateText(it.take(4096), "scan-resume-uri") }
   dao.upsertScanSessionState(if (existing == null) ScanSessionState(
    sessionId = sessionId, scanType = normalized, operationType = operationType,
    sourceUri = encryptedUri, packageName = packageName, isManual = isManual
   ) else existing.copy(scanType = normalized, operationType = operationType,
    sourceUri = existing.sourceUri ?: encryptedUri, packageName = packageName ?: existing.packageName,
    isManual = isManual, isComplete = false))
  }
 }
 suspend fun resumeScanSession(sessionId: String) = withContext(Dispatchers.IO) {
  database.threatDao().markScanSessionResumed(sessionId)
 }
 suspend fun scanSessionState(sessionId: String): ScanSessionState? = withContext(Dispatchers.IO) {
  database.threatDao().findScanSessionState(sessionId)?.let { state ->
   state.copy(currentItemPath = state.currentItemPath?.let { revealPrivateTextSafely(it, "scan-progress-path") },
    sourceUri = state.sourceUri?.let { revealPrivateTextSafely(it, "scan-resume-uri") })
  }
 }
 suspend fun latestIncompleteManualScanState(): ScanSessionState? = withContext(Dispatchers.IO) {
  database.threatDao().latestIncompleteManualScanState()?.let { state ->
   state.copy(currentItemPath = state.currentItemPath?.let { revealPrivateTextSafely(it, "scan-progress-path") },
    sourceUri = state.sourceUri?.let { revealPrivateTextSafely(it, "scan-resume-uri") })
  }
 }
 suspend fun hasIncompleteManualScanSession(): Boolean = withContext(Dispatchers.IO) {
  database.threatDao().hasIncompleteManualScanSession()
 }
 fun observeLatestScanState(): Flow<ScanSessionState?> =
  database.threatDao().observeLatestScanState().map { state ->
   state?.copy(currentItemPath = state.currentItemPath?.let { revealPrivateTextSafely(it, "scan-progress-path") })
  }.flowOn(Dispatchers.IO)
 suspend fun updateScanSessionTotal(sessionId: String, totalItems: Int) = withContext(Dispatchers.IO) {
  database.threatDao().updateScanSessionTotal(sessionId, totalItems.coerceAtLeast(0))
 }
 suspend fun recordScanItemCompleted(sessionId: String, itemKey: String, itemType: String, result: ScanResult) = withContext(Dispatchers.IO) {
  val counters = scanPublishCounters.computeIfAbsent(sessionId) { ScanPublishCounters() }
  counters.totalPackages.incrementAndGet()
  var stage = "encrypt"
  try {
   database.withTransaction {
    val dao = database.threatDao()
    val path = privateTextStore.protectPrivateText(result.displayName.take(250), "scan-progress-path")
    val reasons = privateTextStore.protectPrivateText(result.reasons.joinToString("\n").take(1024), "scan-progress-reasons")
    val uri = result.sourceUri?.let { privateTextStore.protectPrivateText(it.take(4096), "scan-progress-uri") }
    stage = "room_insert"
    dao.insertScanSessionItem(
     ScanSessionItemEntity(
      sessionId = sessionId, itemKey = itemKey, itemType = itemType, itemPath = path,
      verdict = result.verdict.name, packageName = result.packageName,
      sha256Hash = result.sha256, md5Hash = result.md5, reasons = reasons,
      riskScore = result.riskScore, detectionSource = result.detectionSource.name,
      malwareName = result.malwareName, threatEventId = result.threatEventId,
      durationMs = result.durationMs, sourceUri = uri,
      completedAt = System.currentTimeMillis(), apkSizeBytes = result.apkSizeBytes,
      scanSource = result.scanSource.name, analysisStages = result.analysisStages.joinToString(",")
     )
    )
    dao.updateScanSessionProgress(sessionId, dao.countScanSessionItems(sessionId), path)
   }
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   counters.failureCount.incrementAndGet()
   throw ScanPublishStageException(stage, error)
  }
 }

 suspend fun loadScanSessionResults(sessionId: String): List<ScanResult> = withContext(Dispatchers.IO) {
  database.threatDao().scanSessionItems(sessionId).mapNotNull { item ->
   val packageName = PersistedScanResultPolicy.packageNameFromPersistedRow(
    itemType = item.itemType,
    itemKey = item.itemKey,
    storedPackageName = item.packageName
   )
   if (!PersistedScanResultPolicy.hasDisplayableIdentity(item.itemType, packageName)) {
    Log.w("ScanDebug", "session_row_skip sessionId=$sessionId itemKey=${item.itemKey} reason=app_package_identity_missing")
    return@mapNotNull null
   }
   val verdict = try {
    ScanVerdict.valueOf(item.verdict)
   } catch (error: Exception) {
    Log.e("ScanDebug", "session_row_skip sessionId=$sessionId itemKey=${item.itemKey} pkg=$packageName reason=invalid_verdict value=${item.verdict}", error)
    return@mapNotNull null
   }
   val path = revealPrivateTextSafely(item.itemPath, "scan-progress-path")
   val reasons = revealPrivateTextSafely(item.reasons, "scan-progress-reasons").split("\n").filter { it.isNotBlank() }
   val uri = item.sourceUri?.let { revealPrivateTextSafely(it, "scan-progress-uri") }
   val source = try {
    com.vibesync.antivirus.core.engine.DetectionSource.valueOf(item.detectionSource)
   } catch (error: Exception) {
    Log.e("ScanDebug", "session_row_metadata_fallback sessionId=$sessionId itemKey=${item.itemKey} pkg=$packageName field=detection_source value=${item.detectionSource}", error)
    com.vibesync.antivirus.core.engine.DetectionSource.NONE
   }
   val sourceKind = runCatching {
    com.vibesync.antivirus.core.engine.ScanSource.valueOf(item.scanSource)
   }.getOrDefault(com.vibesync.antivirus.core.engine.ScanSource.FRESH)
   val restored = ScanResult(
    path, path, item.sha256Hash, item.md5Hash, verdict, reasons, item.durationMs,
    packageName = packageName, sourceUri = uri, scanSessionId = sessionId,
    threatEventId = item.threatEventId, riskScore = item.riskScore,
    detectionSource = source, malwareName = item.malwareName,
    apkSizeBytes = item.apkSizeBytes, scanSource = sourceKind,
    analysisStages = item.analysisStages.split(",").filter { it.isNotBlank() }
   )
   PersistedScanResultPolicy.normalizeOfficialGoogleResult(
    restored,
    item.packageName?.let {
     com.vibesync.antivirus.core.security.OfficialGoogleAppPolicy.isOfficialGooglePackage(context, it)
    } == true
   )
  }
 }
 
 /**
  * One persisted-row selector for restored Scan & Lab results and scan-report summaries.
  */
 suspend fun reviewableScanResults(results: List<ScanResult>): List<ScanResult> =
  PersistedScanResultPolicy.selectVisiblePersistedResults(results) { result ->
   isReviewableResult(result)
  }

 suspend fun latestCompletedScanResults(): List<ScanResult> = withContext(Dispatchers.IO) {
  val state = database.threatDao().latestCompletedScanState() ?: return@withContext emptyList()
  reviewableScanResults(loadScanSessionResults(state.sessionId))
 }
 suspend fun scanSessionStartedAt(sessionId: String): Long? = withContext(Dispatchers.IO) {
  database.threatDao().findScanSession(sessionId)?.startedAt
 }
 suspend fun scanSessionElapsedMs(sessionId: String): Long? = withContext(Dispatchers.IO) {
  database.threatDao().findScanSession(sessionId)?.elapsedMs
 }
 suspend fun addScanSessionElapsedMs(sessionId: String, elapsedMs: Long) = withContext(Dispatchers.IO) {
  if (elapsedMs > 0L) database.threatDao().addScanSessionElapsedMs(sessionId, elapsedMs)
 }

 suspend fun completeScanSession(sessionId: String, completedAt: Long = System.currentTimeMillis()) = withContext(Dispatchers.IO) {
  database.withTransaction {
   val dao = database.threatDao()
   dao.markScanSessionCompleted(sessionId, completedAt)
   dao.markScanSessionStateComplete(sessionId, dao.countScanSessionItems(sessionId))
  }
  safInventorySnapshots.remove(sessionId)
 }
 suspend fun interruptScanSession(sessionId: String) = withContext(Dispatchers.IO) {
  database.threatDao().markScanSessionInterrupted(sessionId, System.currentTimeMillis())
  safInventorySnapshots.remove(sessionId)
 }
 /** Runtime failure is terminal for this attempt; Room items remain available for review. */
 suspend fun failScanSession(sessionId: String) = withContext(Dispatchers.IO) {
  database.withTransaction {
   val dao = database.threatDao()
   dao.markScanSessionInterrupted(sessionId, System.currentTimeMillis())
   dao.markScanSessionStateComplete(sessionId, dao.countScanSessionItems(sessionId))
  }
  safInventorySnapshots.remove(sessionId)
 }
 /** Explicit Stop Scan is terminal; process/service interruptions remain resumable. */
 suspend fun cancelScanSession(sessionId: String) = withContext(Dispatchers.IO) {
  database.withTransaction {
   val dao = database.threatDao()
   dao.markScanSessionInterrupted(sessionId, System.currentTimeMillis())
   dao.markScanSessionStateComplete(sessionId, dao.countScanSessionItems(sessionId))
  }
  safInventorySnapshots.remove(sessionId)
 }
 private fun fileItemKey(uri: Uri): String {
  val hash = MessageDigest.getInstance("SHA-256").digest(uri.toString().toByteArray(Charsets.UTF_8))
  return "file:" + hash.joinToString("") { "%02x".format(it) }
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
   appCount = p.getInt("apps", 0), fileCount = p.getInt("files", 0),
   threats = p.getInt("threats", 0), review = p.getInt("review", 0),
   unreadable = p.getInt("unreadable", 0), completedAt = time,
   signedDefinitionsUsed = p.getBoolean("signed_definitions_used", false),
   skippedFiles = p.getInt("skipped_files", 0),
   startedAt = p.getLong("started_at", time), elapsedMs = p.getLong("elapsed_ms", 0L),
   totalApkBytes = p.getLong("total_apk_bytes", 0L), scannedApkBytes = p.getLong("scanned_apk_bytes", 0L),
   completedAppCount = p.getInt("completed_app_count", p.getInt("apps", 0)),
   appsPerSecond = p.getFloat("apps_per_second", 0f).toDouble(),
   mbPerSecond = p.getFloat("mb_per_second", 0f).toDouble(),
   pendingRetries = p.getInt("pending_retries", p.getInt("unreadable", 0)),
   cachedAppCount = p.getInt("cached_apps", 0), freshAppCount = p.getInt("fresh_apps", 0),
   verifiedGoogleAppCount = p.getInt("google_verified_apps", 0),
   enumeratedPackages = p.getInt("enumerated_packages", 0),
   queuedPackages = p.getInt("queued_packages", 0), excludedPackages = p.getInt("excluded_packages", 0))
 }.getOrNull()
 fun saveScanSummary(summary: com.vibesync.antivirus.core.engine.ScanCompletionSummary) {
  context.getSharedPreferences("safe_mobile_last_scan", Context.MODE_PRIVATE).edit()
   .putInt("apps", summary.appCount).putInt("files", summary.fileCount).putInt("threats", summary.threats)
   .putInt("review", summary.review).putInt("unreadable", summary.unreadable)
   .putInt("skipped_files", summary.skippedFiles).putLong("completed_at", summary.completedAt)
   .putLong("started_at", summary.startedAt).putLong("elapsed_ms", summary.elapsedMs)
   .putLong("total_apk_bytes", summary.totalApkBytes).putLong("scanned_apk_bytes", summary.scannedApkBytes)
   .putInt("completed_app_count", summary.completedAppCount)
   .putFloat("apps_per_second", summary.appsPerSecond.toFloat())
   .putFloat("mb_per_second", summary.mbPerSecond.toFloat())
   .putInt("pending_retries", summary.pendingRetries)
   .putInt("cached_apps", summary.cachedAppCount).putInt("fresh_apps", summary.freshAppCount)
   .putInt("google_verified_apps", summary.verifiedGoogleAppCount)
   .putInt("enumerated_packages", summary.enumeratedPackages)
   .putInt("queued_packages", summary.queuedPackages).putInt("excluded_packages", summary.excludedPackages)
   .putBoolean("signed_definitions_used", summary.signedDefinitionsUsed).apply()
 }

 fun observeScanSessionCounts(): Flow<ScanSessionCounts> =
  database.threatDao().observeScanSessionCounts()

 fun observeLatestCompletedScanAt(): Flow<Long?> =
  database.threatDao().observeLatestCompletedScanAt()

 suspend fun latestCompletedScanAt(): Long? = withContext(Dispatchers.IO) {
  database.threatDao().latestCompletedScanAt()
 }

 fun observeRecentAudits(): Flow<List<ScanAudit>> =
  database.threatDao().observeRecentAudits().map { rows ->
   rows.map { row -> row.copy(packageOrPath = revealPrivateTextSafely(row.packageOrPath, "scan-label")) }
  }

 fun observeAnalytics(week: AnalyticsWeek): Flow<ScanAnalytics> = combine(
  database.threatDao().observeOutcomeTotals(),
  database.threatDao().observeWeeklySessions(week.startMillis, week.endMillis)
 ) { totals, days -> ScanAnalytics(totals, week.counts(days)) }.flowOn(Dispatchers.IO)

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
  val packageName = result.packageName ?: return@withContext true
  val eligible = isEligibleInstalledApp(packageName)
  if (!eligible) {
   val reason = when {
    packageName == context.packageName -> "consumer_review_filter_own_package"
    TrustedPackageWhitelist.hasProtectedNamespace(packageName) -> "consumer_review_filter_protected_namespace"
    else -> "consumer_review_filter_system_flags_or_package_lookup"
   }
   val userId = android.os.Process.myUid() / 100000
   Log.i("ScanDebug", "pkg_skipped pkg=$packageName reason=$reason userId=$userId source=review_filter")
  }
  eligible
 }

 private fun isEligibleInstalledApp(name: String): Boolean =
  TrustedPackageWhitelist.isEligibleForReview(context, name)

 private fun revealPrivateTextSafely(value: String, purpose: String): String =
  try {
   privateTextStore.revealPrivateText(value, purpose)
  } catch (error: Exception) {
   Log.e("ScanDebug", "session_metadata_decode_failed purpose=$purpose", error)
   "[Encrypted local metadata unavailable]"
  }
 fun observeActiveThreatIndicatorCount(): Flow<Int> = threatIntelligence.observeActiveIndicatorCount()
 fun observeLastSuccessfulThreatFeedSyncAt(): Flow<Long?> = threatIntelligence.observeLastSuccessfulSyncAt()
 fun observeLatestThreatFeedSyncState(): Flow<ThreatFeedSyncStateEntity?> = threatIntelligence.observeLatestSyncState()
 fun observeThreatFeedSnapshot() = threatIntelligence.observeSnapshot()
 suspend fun loadThreatFeedSnapshot() = threatIntelligence.loadSnapshot()
 fun requestThreatFeedSync() = ThreatFeedSyncScheduler.enqueueNow(context)
 suspend fun lookupThreatHash(sha256: String?, md5: String?) = threatIntelligence.lookupHash(sha256, md5)
 suspend fun lookupNetworkIoc(value: String) = threatIntelligence.lookupIoc(value)
 suspend fun lookupDomain(domain: String) = threatIntelligence.lookupDomain(domain)
 suspend fun lookupIpAddress(ipAddress: String) = threatIntelligence.lookupIpAddress(ipAddress)
 suspend fun getActiveThreatIndicatorCount(): Int = threatIntelligence.getActiveSignatureCount()
 fun observeActiveSignatureCount(): Flow<Int> = threatIntelligence.observeActiveSignatureCount()
 fun observeLastSuccessfulThreatFeedSyncTime(): Flow<Long?> = threatIntelligence.observeLastSuccessfulSyncTime()
 fun syncThreatFeeds() = requestThreatFeedSync()
 suspend fun scanInstalledApps(progress: suspend (Int, Int) -> Unit = { _, _ -> }): List<ScanResult> =
  scanInstalledAppsForSession(UUID.randomUUID().toString(), progress)

 suspend fun scanInstalledAppsForSession(
  scanSessionId: String, progress: suspend (Int, Int) -> Unit = { _, _ -> }
 ): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  val done = database.threatDao().scanSessionItemKeys(scanSessionId)
   .filter { it.startsWith("app:") }.map { it.removePrefix("app:") }.toSet()
  withInstalledAppScanTimeout {
   scanner.scanInstalledAppsForSession(scanSessionId, completedPackageNames = done,
    onItemCompleted = { result ->
     Log.d("ScanDebug", "Scanning: ${result.packageName ?: result.displayName}")
     recordScanItemCompleted(scanSessionId, "app:" + (result.packageName ?: result.displayName), "app", result)
    },
    progress = { scanned, total -> updateScanSessionTotal(scanSessionId, total); progress(scanned, total) })
  }
 }

 /** Scan installed APKs and files in the user's persisted SAF folder, with bounded traversal. */
 suspend fun scanFull(progress: suspend (Int, Int) -> Unit = { _, _ -> }): List<ScanResult> =
  scanFullForSession(UUID.randomUUID().toString(), progress)

 suspend fun scanFullForSession(
  scanSessionId: String, progress: suspend (Int, Int) -> Unit = { _, _ -> }
 ): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  val files = selectedFolderFiles(scanSessionId)
  val done = database.threatDao().scanSessionItemKeys(scanSessionId).toSet()
  val doneFiles = files.count { fileItemKey(it.uri) in done }
  val doneApps = done.filter { it.startsWith("app:") }.map { it.removePrefix("app:") }.toSet()
  var appProgress = doneApps.size
  var appTotal = 0
  val appResults = withInstalledAppScanTimeout {
   scanner.scanInstalledAppsForSession(scanSessionId,
    completedPackageNames = doneApps,
    onItemCompleted = { result ->
     Log.d("ScanDebug", "Scanning: ${result.packageName ?: result.displayName}")
     recordScanItemCompleted(scanSessionId, "app:" + (result.packageName ?: result.displayName), "app", result)
    },
    progress = { scanned, total ->
     appProgress = scanned; appTotal = total
     val all = (total.toLong() + files.size).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
     updateScanSessionTotal(scanSessionId, all)
     progress((scanned.toLong() + doneFiles).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), all)
    })
  }
  val fileResults = ArrayList<ScanResult>()
  var fileProgress = doneFiles
  for (file in files) {
   currentCoroutineContext().ensureActive()
   if (fileItemKey(file.uri) in done) continue
   Log.d("ScanDebug", "Scanning: ${file.displayName}")
   val result = scanSafFile(file.uri, file.displayName, scanSessionId)
   try {
      recordScanItemCompleted(scanSessionId, fileItemKey(file.uri), "file", result)
     } catch (cancelled: CancellationException) {
      throw cancelled
     } catch (error: Exception) {
      Log.e("SafeMobileScan", "Publish failed", error)
     }
   if (result.verdict != ScanVerdict.NO_MATCH) fileResults += result
   fileProgress++
   val all = (appTotal.toLong() + files.size).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
   progress((appProgress.toLong() + fileProgress).coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), all)
  }
  val total = (appTotal.toLong() + files.size).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
  progress(total, total)
  appResults + fileResults
 }

 /** Deep-scan readable files below one user-selected SAF tree, without widening the grant. */
 suspend fun scanFolderTree(
   treeUri: Uri,
   progress: suspend (Int, Int) -> Unit = { _, _ -> },
   onFileStarted: suspend (String) -> Unit = {}
  ): List<ScanResult> =
   scanFolderTreeForSession(treeUri, UUID.randomUUID().toString(), progress, onFileStarted)

 suspend fun scanFolderTreeForSession(
   treeUri: Uri, scanSessionId: String,
   progress: suspend (Int, Int) -> Unit = { _, _ -> },
   onFileStarted: suspend (String) -> Unit = {}
  ): List<ScanResult> = withContext(Dispatchers.IO) {
   // SafTreeWalker validates provider access for each entry and isolates per-entry failures.
   definitionLoader.importBundledIfEmpty()
   val candidates = selectedSafFilesForSession(scanSessionId, listOf(treeUri))
   val done = database.threatDao().scanSessionItemKeys(scanSessionId).toSet()
   val count = candidates.count { fileItemKey(it.uri) in done }
   val pending = candidates.filterNot { fileItemKey(it.uri) in done }
   val total = candidates.size
   updateScanSessionTotal(scanSessionId, total)
   val findings = ArrayList<ScanResult>()
   progress(count, total)
   pending.forEachIndexed { index, file ->
    currentCoroutineContext().ensureActive()
    val label = file.displayName
    onFileStarted(label)
    Log.d("ScanDebug", "Scanning: $label")
    val result = scanSafFile(file.uri, label, scanSessionId)
    try {
      recordScanItemCompleted(scanSessionId, fileItemKey(file.uri), "file", result)
     } catch (cancelled: CancellationException) {
      throw cancelled
     } catch (error: Exception) {
      Log.e("SafeMobileScan", "Publish failed", error)
     }
    if (result.verdict != ScanVerdict.NO_MATCH) findings += result
    progress(count + index + 1, total)
   }
   findings
  }

 private data class SelectedFolderFile(val uri: Uri, val displayName: String)

 /**
  * Enumerate explicit SAF grants once per scan session. The same immutable snapshot is
  * reused for in-process retry passes, so a NOT_SCANNED retry does not walk the tree again.
  * A changed root set or a new scan session produces a fresh inventory.
  */
 private suspend fun selectedFolderFiles(scanSessionId: String): List<SelectedFolderFile> =
  selectedSafFilesForSession(scanSessionId, StorageAccessPreferences.accessibleTreeUris(context))

 private suspend fun selectedSafFilesForSession(
  scanSessionId: String,
  roots: List<Uri>
 ): List<SelectedFolderFile> = withContext(Dispatchers.IO) {
  val uniqueRoots = roots.distinctBy { it.toString() }
  val rootsKey = uniqueRoots.map { it.toString() }.sorted().joinToString("\u001f")
  safInventorySnapshots.getOrLoad(scanSessionId, rootsKey) {
   com.vibesync.antivirus.core.observer.SafTreeWalker.files(
    context, uniqueRoots, maxDepth = 10, maxFiles = maxSafScanFiles,
    onFileError = { uri, error -> recordSkippedSafFile(scanSessionId, uri, error) }
   ).map { file ->
    val displayName = file.uri.lastPathSegment?.take(250)?.takeIf { it.isNotBlank() }
     ?: context.getString(R.string.unknown_file)
    SelectedFolderFile(file.uri, displayName)
   }.toList()
  }
 }

 private fun encryptPrivateText(value: String?, purpose: String): String? =
  value?.takeIf { it.isNotEmpty() }?.let { privateTextStore.protectPrivateText(it.take(1024), purpose) }

 private fun decryptPrivateText(value: String?, purpose: String): String? =
  value?.let { revealPrivateTextSafely(it, purpose) }

 suspend fun scanInstalledPackage(name: String, scanSessionId: String = UUID.randomUUID().toString()): ScanResult? = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanInstalledPackage(name, scanSessionId)
 }
 suspend fun scanFile(file: File): ScanResult = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  applyTrustedFileHash(scanner.scanFile(file))
 }
 suspend fun scanUri(uri: Uri, scanSessionId: String = UUID.randomUUID().toString()): ScanResult = withContext(Dispatchers.IO) {
  val quarantineManager = LocalQuarantineManager(context)
  val label = uri.lastPathSegment?.takeIf { it.isNotBlank() } ?: context.getString(R.string.unknown_file)
  if (!quarantineManager.supportsLocalUri(uri)) {
   return@withContext recordUnscannedUri(label, context.getString(R.string.local_files_only), scanSessionId)
  }
  definitionLoader.importBundledIfEmpty()
  applyTrustedFileHash(scanSafFile(uri, label, scanSessionId))
 }

 suspend fun scanUriForSession(uri: Uri, scanSessionId: String): ScanResult = withContext(Dispatchers.IO) {
  updateScanSessionTotal(scanSessionId, 1)
  val result = scanUri(uri, scanSessionId)
  recordScanItemCompleted(scanSessionId, fileItemKey(uri), "file", result)
  result
 }
 suspend fun scanInstalledPackageForSession(packageName: String, scanSessionId: String): ScanResult? = withContext(Dispatchers.IO) {
  updateScanSessionTotal(scanSessionId, 1)
  val result = scanInstalledPackage(packageName, scanSessionId)
  if (result != null) recordScanItemCompleted(scanSessionId, "app:$packageName", "app", result)
  result
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
 suspend fun quarantineSelectedFile(uri: Uri, expectedSha256: String?): QuarantineOutcome = withContext(Dispatchers.IO) {
  // Authenticate the encrypted vault copy before asking Android to remove the source document.
  LocalQuarantineManager(context).quarantine(uri, expectedSha256, removeOriginalAfterVerified = true)
 }

 suspend fun listQuarantinedFiles(): List<File> = withContext(Dispatchers.IO) {
  LocalQuarantineManager(context).listQuarantinedFiles()
 }
 suspend fun restoreQuarantinedFile(file: File, destinationUri: Uri): UiText = withContext(Dispatchers.IO) {
  val manager = LocalQuarantineManager(context)
  val label = manager.displayName(file)
  val bytes = manager.restoreToUri(file, destinationUri)
  UiText(R.string.restore_result_localized, listOf(label, UiText(R.plurals.l10n_bytes, listOf(bytes), bytes.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())))
 }
 suspend fun deleteQuarantinedFile(file: File): UiText = withContext(Dispatchers.IO) {
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
   QuarantineDeleteOutcome.DELETED -> UiText(R.string.quarantine_delete_success, listOf(label))
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

 suspend fun importPendingYaraRule(uri: Uri): UiText = withContext(Dispatchers.IO) {
  val stream = context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  val saved = YaraRuleImportStore(context).importPending(stream)
  UiText(R.string.rule_import_pending, listOf(saved.name))
 }

suspend fun importOfflineDefinitions(uri: Uri): UiText = withContext(Dispatchers.IO) {
  val stream=context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  definitionLoader.importFromStream(stream).let { UiText(R.plurals.l10n_imported, listOf(it), it) }
 }
 suspend fun signatureCount(): Int = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  database.threatDao().countSignatures()
 }
 suspend fun deepScan(scanSessionId: String = UUID.randomUUID().toString()): List<ScanResult> = scanFullForSession(scanSessionId)

 companion object {
  private const val TRUSTED_FILE_HASHES_PREFS = "safemobile_trusted_file_hashes"
  private const val TRUSTED_FILE_HASHES_KEY = "sha256"
 }
}

