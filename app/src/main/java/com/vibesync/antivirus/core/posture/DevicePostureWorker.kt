package com.vibesync.antivirus.core.posture

import android.content.Context
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CancellationException

class DevicePostureWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val repository = (applicationContext as? SafeMobileApp)?.devicePostureRepository ?: return Result.failure()
        return try {
            if (repository.monitor()) Result.success() else Result.retry()
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) {
            // Never log package identifiers, snapshots, decrypted content, or crypto material.
            Log.w("SafeMobilePosture", "Posture comparison could not complete; encrypted baseline retained")
            repository.reportStorageError()
            Result.retry()
        }
    }
}
