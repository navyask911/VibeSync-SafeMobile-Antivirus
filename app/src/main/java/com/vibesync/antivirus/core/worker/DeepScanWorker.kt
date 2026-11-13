package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CancellationException

/** Periodic full-device scan promoted to an explicit foreground WorkManager task. */
class DeepScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

 override suspend fun getForegroundInfo(): ForegroundInfo =
  ScanForegroundNotifications.create(
   applicationContext,
   ScanForegroundNotifications.notificationId(id)
  )

 override suspend fun doWork(): Result {
  val app = applicationContext as? SafeMobileApp ?: return Result.failure()
  val sessionId = id.toString()
  return try {
   setForeground(getForegroundInfo())
   app.repository.startScanSession(sessionId, "PERIODIC_DEEP_SCAN")
   app.repository.deepScan(sessionId)
   app.repository.completeScanSession(sessionId)
   Result.success()
  } catch (cancelled: CancellationException) {
   runCatching { app.repository.interruptScanSession(sessionId) }
   throw cancelled
  } catch (_: Exception) {
   runCatching { app.repository.interruptScanSession(sessionId) }
   if (runAttemptCount < 3) Result.retry() else Result.failure()
  }
 }

 companion object { const val UNIQUE_NAME = "safe_mobile_periodic_deep_scan" }
}
