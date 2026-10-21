package com.vibesync.antivirus.core.worker
import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CancellationException

class DeepScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
 override suspend fun doWork(): Result = try {
  (applicationContext as SafeMobileApp).repository.deepScan()
  Result.success()
 } catch (cancelled: CancellationException) {
  throw cancelled
 } catch (_: Exception) {
  if (runAttemptCount < 3) Result.retry() else Result.failure()
 }
 companion object { const val UNIQUE_NAME = "safe_mobile_periodic_deep_scan" }
}
