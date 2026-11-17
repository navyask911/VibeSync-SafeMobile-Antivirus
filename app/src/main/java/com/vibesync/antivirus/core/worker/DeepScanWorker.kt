package com.vibesync.antivirus.core.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.withLock

/** Periodic full-device scan promoted to an explicit foreground WorkManager task. */
class DeepScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

 override suspend fun getForegroundInfo(): ForegroundInfo =
  ScanForegroundNotifications.create(
   applicationContext,
   ScanForegroundNotifications.notificationId(id)
  )

 override suspend fun doWork(): Result {
  Log.d("ScanDebug", "Worker STARTED for: $tags")
  return ScanExecutionCoordinator.mutex.withLock {
   var app: SafeMobileApp? = null
   var sessionId: String? = null
   try {
    val safeApp = applicationContext as? SafeMobileApp
     ?: throw IllegalStateException("SafeMobileApp application is unavailable.")
    app = safeApp
    sessionId = id.toString()
    setForeground(getForegroundInfo())
    safeApp.repository.clearScanSessionStateCheckpoints()
    safeApp.repository.startScanSession(sessionId, "PERIODIC_DEEP_SCAN", isManual = false)
    safeApp.repository.deepScan(sessionId)
    safeApp.repository.completeScanSession(sessionId)
    val result = Result.success()
    Log.d("ScanDebug", "Worker FINISHED with result: $result")
    result
   } catch (cancelled: CancellationException) {
    sessionId?.let { activeId -> runCatching { app?.repository?.interruptScanSession(activeId) } }
    throw cancelled
   } catch (error: Exception) {
    sessionId?.let { activeId -> runCatching { app?.repository?.interruptScanSession(activeId) } }
    runCatching { app?.repository?.clearScanSessionStateCheckpoints() }
    Log.e("ScanDebug", "Worker CRASHED", error)
    val result = Result.failure()
    Log.d("ScanDebug", "Worker FINISHED with result: $result")
    result
   }
  }
 }

 companion object { const val UNIQUE_NAME = "safe_mobile_periodic_deep_scan" }
}
