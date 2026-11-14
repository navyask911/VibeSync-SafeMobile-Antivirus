package com.vibesync.antivirus.core.worker
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.IBinder
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
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

data class ScanCompletedEvent(val sessionId: String, val results: List<ScanResult>, val summary: ScanCompletionSummary, val manualScan: Boolean)
object ScanForegroundEvents {
 private val done = MutableSharedFlow<ScanCompletedEvent>(extraBufferCapacity = 1)
 private val stopped = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
 val completed = done.asSharedFlow()
 val cancelled = stopped.asSharedFlow()
 fun publish(event: ScanCompletedEvent) { done.tryEmit(event) }
 fun publishCancelled() { stopped.tryEmit(Unit) }
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
   runScan(intent?.getStringExtra(EXTRA_OPERATION_TYPE), intent?.getStringExtra(EXTRA_SOURCE_URI),
    intent?.getStringExtra(EXTRA_PACKAGE_NAME), intent?.getBooleanExtra(EXTRA_MANUAL_SCAN, true) ?: true)
  }
  return START_STICKY
 }
 private suspend fun runScan(operation: String?, uriValue: String?, packageValue: String?, manual: Boolean) {
  val repo = (application as? SafeMobileApp)?.repository ?: run { stopServiceAfterRun(); return }
  var sessionId: String? = null
  try {
   val previous = repo.latestIncompleteManualScanState()
   val session = if (previous != null) {
    repo.resumeScanSession(previous.sessionId); previous
   } else {
    val op = operation?.takeIf { it != OP_RESUME } ?: run { stopServiceAfterRun(); return }
    val newId = UUID.randomUUID().toString()
    val kind = if (op == OP_DEEP_SCAN || op == OP_SELECTED_FOLDER) "DEEP_SCAN" else "FULL_SCAN"
    repo.startScanSession(newId, kind, op, uriValue, packageValue, manual)
    repo.scanSessionState(newId) ?: error("Room scan state missing.")
   }
   sessionId = session.sessionId
   if (stopRequested) {
    repo.cancelScanSession(session.sessionId); ScanForegroundEvents.publishCancelled(); return
   }
   when (session.operationType) {
    OP_FULL_DEVICE, OP_DEEP_SCAN -> repo.scanFullForSession(session.sessionId)
    OP_INSTALLED_APPS -> repo.scanInstalledAppsForSession(session.sessionId)
    OP_SELECTED_FILE -> repo.scanUriForSession(session.sourceUri?.let(Uri::parse) ?: error("Selected file URI missing."), session.sessionId)
    OP_INSTALLED_PACKAGE -> repo.scanInstalledPackageForSession(session.packageName ?: error("Package name missing."), session.sessionId)
    OP_SELECTED_FOLDER -> repo.scanFolderTreeForSession(session.sourceUri?.let(Uri::parse) ?: error("Selected folder URI missing."), session.sessionId)
    else -> error("Unsupported scan operation: " + session.operationType)
   }
   if (stopRequested) {
    repo.cancelScanSession(session.sessionId); ScanForegroundEvents.publishCancelled(); return
   }
   val results = repo.loadScanSessionResults(session.sessionId).filter { repo.isReviewableResult(it) }
    .sortedBy { when (it.verdict) {
     ScanVerdict.THREAT -> 0
     ScanVerdict.SUSPICIOUS -> 1
     ScanVerdict.NOT_SCANNED -> 2
     ScanVerdict.NO_MATCH -> 3
    } }
   val current = repo.scanSessionState(session.sessionId)
   val summary = ScanCompletionSummary.from(results, current?.scannedItems ?: results.size,
    System.currentTimeMillis()).copy(signedDefinitionsUsed = repo.currentHashDatabaseCapability()?.enabled == true)
   repo.saveScanSummary(summary)
   repo.completeScanSession(session.sessionId, summary.completedAt)
   ScanForegroundEvents.publish(ScanCompletedEvent(session.sessionId, results, summary, session.isManual))
  } catch (cancelled: CancellationException) {
   sessionId?.let { id ->
    if (stopRequested) { runCatching { repo.cancelScanSession(id) }; ScanForegroundEvents.publishCancelled() }
    else runCatching { repo.interruptScanSession(id) }
   }
   throw cancelled
  } catch (error: Exception) {
   sessionId?.let { runCatching { repo.interruptScanSession(it) } }
   Log.e("SafeMobileScan", "Scan failed; Room checkpoints retained for resume.", error)
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
  fun start(context: Context, operation: String, manual: Boolean = true, uri: String? = null, packageName: String? = null) {
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
