package com.vibesync.antivirus.data.repository
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.quarantine.LocalQuarantineManager
import com.vibesync.antivirus.core.worker.LocalDefinitionLoader
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import com.vibesync.antivirus.core.worker.ThreatFeedSyncScheduler
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
 fun observeRecentAudits(): Flow<List<ScanAudit>> = database.threatDao().observeRecentAudits()
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
     packageOrPath = label.take(250),
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
 suspend fun quarantineSelectedFile(uri: Uri, expectedSha256: String?): String = withContext(Dispatchers.IO) {
  val outcome = LocalQuarantineManager(context).quarantine(uri, expectedSha256)
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
  val label = manager.displayName(file)
  if (!manager.deleteQuarantinedFile(file)) throw IOException("Could not permanently delete quarantined file.")
  context.getString(R.string.quarantine_delete_success, label)
 }
 suspend fun importOfflineDefinitions(uri: Uri): String = withContext(Dispatchers.IO) {
  val stream=context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  context.getString(R.string.import_success,definitionLoader.importFromStream(stream))
 }
 suspend fun signatureCount(): Int = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  database.threatDao().countSignatures()
 }
 suspend fun deepScan(): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  val results=scanner.scanInstalledApps()
  if(android.os.Build.VERSION.SDK_INT>=android.os.Build.VERSION_CODES.R && android.os.Environment.isExternalStorageManager()) {
   val downloads=android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
   if(downloads.isDirectory) downloads.walkTopDown().maxDepth(3).filter { it.isFile && it.extension.equals("apk",true) }.take(100).forEach { scanner.scanFile(it) }
  }
  results
 }
}
