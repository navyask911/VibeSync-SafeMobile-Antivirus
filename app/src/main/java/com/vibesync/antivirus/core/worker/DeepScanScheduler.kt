package com.vibesync.antivirus.core.worker

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Schedules local-only periodic deep scans without requiring network connectivity. */
object DeepScanScheduler {
    const val WORK_TAG = "ScanWorker"

    fun ensureScheduled(context: Context) {
        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            DeepScanWorker.UNIQUE_NAME, ExistingPeriodicWorkPolicy.UPDATE, periodicRequest()
        )
    }

    /** Clear any stale tagged scan request before a fresh foreground scan. */
    fun resetBeforeManualScan(context: Context) {
        val workManager = WorkManager.getInstance(context.applicationContext)
        workManager.cancelAllWorkByTag(WORK_TAG)
        workManager.enqueueUniquePeriodicWork(
            DeepScanWorker.UNIQUE_NAME, ExistingPeriodicWorkPolicy.UPDATE, periodicRequest()
        )
        Log.d("ScanDebug", "Cancelled stale scan work tagged $WORK_TAG and refreshed periodic deep scan.")
    }

    private fun periodicRequest() =
        PeriodicWorkRequestBuilder<DeepScanWorker>(6, TimeUnit.HOURS)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.NOT_REQUIRED)
                    .setRequiresBatteryNotLow(true)
                    .build()
            )
            .addTag(WORK_TAG)
            .build()
}
