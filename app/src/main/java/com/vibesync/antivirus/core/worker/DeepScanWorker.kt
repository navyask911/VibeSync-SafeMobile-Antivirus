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
  return try {
   ScanExecutionCoordinator.mutex.withLock {
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
     val scanState = safeApp.repository.scanSessionState(sessionId)
     val publishSummary = safeApp.repository.scanPublishSummary(sessionId)
     Log.e("ScanDebug", "Total publish failures: ${publishSummary.failureCount} / ${publishSummary.totalPackages}")
     val scannedItems = scanState?.scannedItems ?: 0
     if (ScanPublishPolicy.shouldFail(scannedItems, publishSummary.failureCount)) {
      safeApp.repository.failScanSession(sessionId)
      safeApp.repository.clearScanPublishSummary(sessionId)
      Log.e("ScanDebug", "Rejecting deep scan completion: persisted=$scannedItems, publishFailures=${publishSummary.failureCount}")
      val result = Result.failure()
      Log.d("ScanDebug", "Worker FINISHED with result: $result")
      result
     } else {
      safeApp.repository.completeScanSession(sessionId)
      safeApp.repository.clearScanPublishSummary(sessionId)
      val result = Result.success()
      Log.d("ScanDebug", "Worker FINISHED with result: $result")
      result
     }
    } catch (cancelled: CancellationException) {
     sessionId?.let { activeId -> runCatching { app?.repository?.interruptScanSession(activeId) } }
     throw cancelled
    } catch (error: Exception) {
     sessionId?.let { activeId ->
      val publishSummary = runCatching { app?.repository?.scanPublishSummary(activeId) }.getOrNull()
      if (publishSummary != null) {
       Log.e("ScanDebug", "Total publish failures: ${publishSummary.failureCount} / ${publishSummary.totalPackages}")
      }
      runCatching { app?.repository?.clearScanPublishSummary(activeId) }
      runCatching { app?.repository?.interruptScanSession(activeId) }
     }
     runCatching { app?.repository?.clearScanSessionStateCheckpoints() }
     Log.e("ScanDebug", "Worker CRASHED", error)
     val result = Result.failure()
     Log.d("ScanDebug", "Worker FINISHED with result: $result")
     result
    }
   }
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   Log.e("ScanDebug", "Worker CRASHED", error)
   val result = Result.failure()
   Log.d("ScanDebug", "Worker FINISHED with result: $result")
   result
  }
 }

 companion object { const val UNIQUE_NAME = "safe_mobile_periodic_deep_scan" }
}
