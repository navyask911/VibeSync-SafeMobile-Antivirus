package com.vibesync.antivirus.core.worker
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.engine.ScanCompletionSummary
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.UUID

data class ScanCompletedEvent(val sessionId: String, val results: List<ScanResult>, val summary: ScanCompletionSummary, val manualScan: Boolean)
data class ScanFailedEvent(val sessionId: String?)
object ScanForegroundEvents {
 private val done = MutableSharedFlow<ScanCompletedEvent>(extraBufferCapacity = 1)
 private val stopped = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
 private val failures = MutableSharedFlow<ScanFailedEvent>(extraBufferCapacity = 1)
 val completed = done.asSharedFlow()
 val cancelled = stopped.asSharedFlow()
 val failed = failures.asSharedFlow()
 fun publish(event: ScanCompletedEvent) { done.tryEmit(event) }
 fun publishCancelled() { stopped.tryEmit(Unit) }
 fun publishFailed(sessionId: String?) { failures.tryEmit(ScanFailedEvent(sessionId)) }
}

/** Scan lifetime is owned by this service, not an Activity or ViewModel. Room is the resume ledger. */
class ScanForegroundService : Service() {
 private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
 private var scanJob: Job? = null
 @Volatile private var stopRequested = false
 override fun onBind(intent: Intent?): IBinder? = null
 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
  if (intent?.action == ACTION_STOP) { stopScan(); return START_NOT_STICKY }
  val n = ScanForegroundNotifications.createService(this)
  if (Build.VERSION.SDK_INT >= 34)
   startForeground(ScanForegroundNotifications.SERVICE_NOTIFICATION_ID, n, ScanForegroundNotifications.serviceForegroundType())
  else startForeground(ScanForegroundNotifications.SERVICE_NOTIFICATION_ID, n)
  if (scanJob?.isActive == true) return START_STICKY
  stopRequested = false
  scanJob = scope.launch {
   try {
    ScanExecutionCoordinator.mutex.withLock {
     runScan(intent?.getStringExtra(EXTRA_OPERATION_TYPE), intent?.getStringExtra(EXTRA_SOURCE_URI),
      intent?.getStringExtra(EXTRA_PACKAGE_NAME), intent?.getBooleanExtra(EXTRA_MANUAL_SCAN, true) ?: true)
    }
   } catch (cancelled: CancellationException) {
    throw cancelled
   } catch (error: Exception) {
    Log.e("SafeMobileScan", "Worker CRASHED", error)
    ScanForegroundEvents.publishFailed(null)
    stopServiceAfterRun()
   }
  }
  return START_STICKY
 }
 private suspend fun runScan(operation: String?, uriValue: String?, packageValue: String?, manual: Boolean) {
  Log.d("ScanDebug", "Worker STARTED for: ScanForegroundService/${operation ?: OP_RESUME}")
  val repo = (application as? SafeMobileApp)?.repository ?: run {
   val error = IllegalStateException("SafeMobileApp repository is unavailable.")
   Log.e("ScanDebug", "Worker CRASHED", error)
   Log.d("ScanDebug", "Worker FINISHED with result: failure")
   stopServiceAfterRun()
   return
  }
  var sessionId: String? = null
  try {
   val session = if (operation == OP_RESUME || operation == null) {
    val previous = repo.latestIncompleteManualScanState()
    if (previous == null) {
     if (operation == OP_RESUME) {
      val error = IllegalStateException("No interrupted scan session is available to resume.")
      Log.e("ScanDebug", "Worker CRASHED", error)
      ScanForegroundEvents.publishFailed(null)
     }
     Log.d("ScanDebug", "Worker FINISHED with result: no resumable session")
     return
    }
    Log.d("ScanDebug", "Resuming interrupted scan session: ${previous.sessionId}")
    repo.resumeScanSession(previous.sessionId)
    previous
   } else {
    // ACTION_START represents a fresh request; don't attach it to an unrelated stale session.
    Log.d("ScanDebug", "Starting a new scan session without deleting prior session checkpoints.")
    val newId = UUID.randomUUID().toString()
    val kind = if (operation == OP_DEEP_SCAN || operation == OP_SELECTED_FOLDER) "DEEP_SCAN" else "FULL_SCAN"
    repo.startScanSession(newId, kind, operation, uriValue, packageValue, manual)
    repo.scanSessionState(newId) ?: error("Room scan state missing.")
   }
   sessionId = session.sessionId
   Log.d("ScanDebug", "Active scan session: ${session.sessionId}; operation=${session.operationType}")
   repo.clearSkippedSafFileCount(session.sessionId)
   if (stopRequested) {
    repo.cancelScanSession(session.sessionId)
    ScanForegroundEvents.publishCancelled()
    Log.d("ScanDebug", "Worker FINISHED with result: cancelled")
    return
   }
   val scanStartedElapsed = SystemClock.elapsedRealtime()
   when (session.operationType) {
    OP_FULL_DEVICE, OP_DEEP_SCAN -> repo.scanFullForSession(session.sessionId)
    OP_INSTALLED_APPS -> repo.scanInstalledAppsForSession(session.sessionId)
    OP_SELECTED_FILE -> repo.scanUriForSession(session.sourceUri?.let(Uri::parse) ?: error("Selected file URI missing."), session.sessionId)
    OP_INSTALLED_PACKAGE -> repo.scanInstalledPackageForSession(session.packageName ?: error("Package name missing."), session.sessionId)
    OP_SELECTED_FOLDER -> repo.scanFolderTreeForSession(session.sourceUri?.let(Uri::parse) ?: error("Selected folder URI missing."), session.sessionId)
    else -> error("Unsupported scan operation: " + session.operationType)
   }
   repo.addScanSessionElapsedMs(
    session.sessionId,
    (SystemClock.elapsedRealtime() - scanStartedElapsed).coerceAtLeast(0L)
   )
   if (stopRequested) {
    repo.cancelScanSession(session.sessionId)
    ScanForegroundEvents.publishCancelled()
    Log.d("ScanDebug", "Worker FINISHED with result: cancelled")
    return
   }
   val current = repo.scanSessionState(session.sessionId)
   val publishSummary = repo.scanPublishSummary(session.sessionId)
   Log.e("ScanDebug", "Total publish failures: ${publishSummary.failureCount} / ${publishSummary.totalPackages}")
   val scannedItems = current?.scannedItems ?: 0
   if (ScanPublishPolicy.shouldFail(scannedItems, publishSummary.failureCount)) {
    repo.failScanSession(session.sessionId)
    repo.clearScanPublishSummary(session.sessionId)
    repo.clearSkippedSafFileCount(session.sessionId)
    Log.e("ScanDebug", "Rejecting scan completion: persisted=$scannedItems, publishFailures=${publishSummary.failureCount}")
    Log.d("ScanDebug", "Worker FINISHED with result: failure; scanned=$scannedItems")
    ScanForegroundEvents.publishFailed(session.sessionId)
    return
   }
   val results = repo.loadScanSessionResults(session.sessionId).filter { repo.isReviewableResult(it) }
    .sortedBy { when (it.verdict) {
     ScanVerdict.THREAT -> 0
     ScanVerdict.SUSPICIOUS -> 1
     ScanVerdict.NOT_SCANNED -> 2
     ScanVerdict.NO_MATCH -> 3
    } }
   val completedAt = System.currentTimeMillis()
   val summary = ScanCompletionSummary.from(
    results = results,
    processed = scannedItems,
    now = completedAt,
    skippedFiles = repo.skippedSafFileCount(session.sessionId),
    startedAt = repo.scanSessionStartedAt(session.sessionId) ?: completedAt,
    elapsedMsOverride = repo.scanSessionElapsedMs(session.sessionId),
    enumeratedPackages = current?.enumeratedItems ?: 0,
    queuedPackages = current?.eligibleItems ?: 0,
    excludedPackages = current?.excludedItems ?: 0
   ).copy(signedDefinitionsUsed = repo.currentHashDatabaseCapability()?.enabled == true)
   repo.saveScanSummary(summary)
   repo.completeScanSession(session.sessionId, summary.completedAt)
   Log.d("ScanDebug", "Worker FINISHED with result: success; scanned=${(summary.appCount + summary.fileCount)}")
   ScanForegroundEvents.publish(ScanCompletedEvent(session.sessionId, results, summary, session.isManual))
   repo.clearSkippedSafFileCount(session.sessionId)
   repo.clearScanPublishSummary(session.sessionId)
  } catch (timeout: TimeoutCancellationException) {
   Log.w("SafeMobileScan", "Retaining unrelated Room scan sessions after this timeout.")
   sessionId?.let { id ->
    val publishSummary = repo.scanPublishSummary(id)
    Log.e("ScanDebug", "Total publish failures: ${publishSummary.failureCount} / ${publishSummary.totalPackages}")
    repo.clearScanPublishSummary(id)
    runCatching { repo.failScanSession(id) }
     .onFailure { Log.e("SafeMobileScan", "Could not persist timed-out scan state.", it) }
   }
   Log.e("ScanDebug", "Worker CRASHED", timeout)
   Log.e("SafeMobileScan", "Installed-app scan exceeded the 300000 ms timeout.", timeout)
   Log.d("ScanDebug", "Worker FINISHED with result: timeout failure")
   ScanForegroundEvents.publishFailed(sessionId)
  } catch (cancelled: CancellationException) {
   sessionId?.let { id ->
    if (stopRequested) {
     runCatching { repo.cancelScanSession(id) }
     ScanForegroundEvents.publishCancelled()
    } else runCatching { repo.interruptScanSession(id) }
    repo.clearScanPublishSummary(id)
   }
   Log.d("ScanDebug", "Worker FINISHED with result: cancelled")
   throw cancelled
  } catch (error: Exception) {
   Log.w("SafeMobileScan", "Retaining unrelated Room scan sessions after this failure.")
   sessionId?.let { id ->
    val publishSummary = repo.scanPublishSummary(id)
    Log.e("ScanDebug", "Total publish failures: ${publishSummary.failureCount} / ${publishSummary.totalPackages}")
    repo.clearScanPublishSummary(id)
    runCatching { repo.failScanSession(id) }
     .onFailure { Log.e("SafeMobileScan", "Could not persist failed scan state.", it) }
   }
   Log.e("ScanDebug", "Worker CRASHED", error)
   Log.e("SafeMobileScan", "Scan failed; corrupted Room scan checkpoints were cleared.", error)
   Log.d("ScanDebug", "Worker FINISHED with result: failure")
   ScanForegroundEvents.publishFailed(sessionId)
  } finally { stopServiceAfterRun() }
 }
 private fun stopScan() {
  stopRequested = true
  if (scanJob?.isActive == true) scanJob?.cancel()
  else scope.launch {
   val repo = (application as? SafeMobileApp)?.repository
   runCatching { repo?.latestIncompleteManualScanState()?.sessionId }.getOrNull()
    ?.let { runCatching { repo?.cancelScanSession(it) } }
   ScanForegroundEvents.publishCancelled()
   stopServiceAfterRun()
  }
 }
 private suspend fun stopServiceAfterRun() {
  withContext(Dispatchers.Main.immediate) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() }
 }
 override fun onDestroy() { scope.cancel(); super.onDestroy() }
 companion object {
  const val ACTION_START = "com.vibesync.antivirus.action.START_SCAN"
  const val ACTION_RESUME = "com.vibesync.antivirus.action.RESUME_SCAN"
  const val ACTION_STOP = "com.vibesync.antivirus.action.STOP_SCAN"
  const val EXTRA_OPERATION_TYPE = "scan.operation_type"
  const val EXTRA_SOURCE_URI = "scan.source_uri"
  const val EXTRA_PACKAGE_NAME = "scan.package_name"
  const val EXTRA_MANUAL_SCAN = "scan.manual"
  const val OP_RESUME = "RESUME"
  const val OP_FULL_DEVICE = "FULL_DEVICE"
  const val OP_DEEP_SCAN = "DEEP_SCAN"
  const val OP_INSTALLED_APPS = "INSTALLED_APPS"
  const val OP_SELECTED_FILE = "SELECTED_FILE"
  const val OP_INSTALLED_PACKAGE = "INSTALLED_PACKAGE"
  const val OP_SELECTED_FOLDER = "SELECTED_FOLDER"
  /**
   * Service commands intentionally carry only scalar values: operation name,
   * manual-scan flag, URI text and package name. Keep framework metadata and
   * UI objects out of Intent extras.
   */
  fun start(context: Context, operation: String, manual: Boolean = true, uri: String? = null, packageName: String? = null) {
   runCatching { DeepScanScheduler.resetBeforeManualScan(context) }
    .onFailure { Log.e("ScanDebug", "Could not reset tagged WorkManager scan jobs before a new scan.", it) }
   val i = Intent(context, ScanForegroundService::class.java).setAction(ACTION_START)
    .putExtra(EXTRA_OPERATION_TYPE, operation).putExtra(EXTRA_MANUAL_SCAN, manual)
   uri?.let { i.putExtra(EXTRA_SOURCE_URI, it) }
   packageName?.let { i.putExtra(EXTRA_PACKAGE_NAME, it) }
   ContextCompat.startForegroundService(context.applicationContext, i)
  }
  fun resume(context: Context) {
   val i = Intent(context, ScanForegroundService::class.java).setAction(ACTION_RESUME).putExtra(EXTRA_OPERATION_TYPE, OP_RESUME)
   ContextCompat.startForegroundService(context.applicationContext, i)
  }
  fun stop(context: Context) {
   context.applicationContext.startService(Intent(context, ScanForegroundService::class.java).setAction(ACTION_STOP))
  }
 }
}
