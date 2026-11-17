package com.vibesync.antivirus.core.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.withLock

/** Durable post-install scan fallback; stays visible as a foreground task while scanning. */
class MultiLayerScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

 override suspend fun getForegroundInfo(): ForegroundInfo =
  ScanForegroundNotifications.create(
   applicationContext,
   ScanForegroundNotifications.notificationId(id)
  )

 override suspend fun doWork(): Result {
  Log.d("SafeMobileScan", "Post-install worker STARTED for: $tags")
  return try {
   ScanExecutionCoordinator.mutex.withLock {
    withContext(Dispatchers.IO) {
    val name = inputData.getString(KEY_PACKAGE_NAME)?.takeIf { it.isNotBlank() }
     ?: return@withContext Result.failure()
    val eventId = inputData.getString(KEY_EVENT_ID)?.takeIf { it.isNotBlank() }
     ?: return@withContext Result.failure()
    val app = applicationContext as? SafeMobileApp
     ?: throw IllegalStateException("SafeMobileApp application is unavailable.")
    val sessionId = id.toString()
    try {
     setForeground(getForegroundInfo())
     app.repository.startScanSession(sessionId, "POST_INSTALL", isManual = false)
     PostInstallScanProcessor.scan(
      applicationContext,
      name,
      eventId,
      inputData.getBoolean(KEY_UPDATED, false),
      scanSessionId = sessionId
     )
     app.repository.completeScanSession(sessionId)
     val result = Result.success()
     Log.d("SafeMobileScan", "Post-install worker FINISHED with result: $result")
     result
    } catch (cancelled: CancellationException) {
     runCatching { app.repository.interruptScanSession(sessionId) }
     throw cancelled
    } catch (error: Exception) {
     runCatching { app.repository.interruptScanSession(sessionId) }
     Log.e("SafeMobileScan", "Worker CRASHED", error)
     val result = Result.failure()
     Log.d("SafeMobileScan", "Post-install worker FINISHED with result: $result")
     result
    }
   }
  } catch (cancelled: CancellationException) {
   throw cancelled
  } catch (error: Exception) {
   Log.e("SafeMobileScan", "Worker CRASHED", error)
   Result.failure()
  }
 }

 companion object {
  const val KEY_PACKAGE_NAME = "multi_layer.package_name"
  const val KEY_EVENT_ID = "multi_layer.event_id"
  const val KEY_UPDATED = "multi_layer.updated"
 }
}
