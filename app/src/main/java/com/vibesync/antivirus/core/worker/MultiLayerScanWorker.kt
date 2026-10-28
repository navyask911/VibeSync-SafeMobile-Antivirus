package com.vibesync.antivirus.core.worker

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Durable fallback if the foreground sentinel is stopped or killed mid-scan. */
class MultiLayerScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
 override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
  val name = inputData.getString(KEY_PACKAGE_NAME)?.takeIf { it.isNotBlank() } ?: return@withContext Result.failure()
  val eventId = inputData.getString(KEY_EVENT_ID)?.takeIf { it.isNotBlank() } ?: return@withContext Result.failure()
  try {
   PostInstallScanProcessor.scan(applicationContext, name, eventId, inputData.getBoolean(KEY_UPDATED, false))
   Result.success()
  } catch (cancelled: CancellationException) { throw cancelled }
  catch (error: Exception) {
   Log.e("SafeMobileScan", "Post-install scan failed; attempt=$runAttemptCount", error)
   if (runAttemptCount < 2) Result.retry() else Result.failure()
  }
 }
 companion object {
  const val KEY_PACKAGE_NAME = "multi_layer.package_name"
  const val KEY_EVENT_ID = "multi_layer.event_id"
  const val KEY_UPDATED = "multi_layer.updated"
 }
}

