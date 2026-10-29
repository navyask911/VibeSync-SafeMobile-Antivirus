package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Downloads research candidates weekly; no remote scanning or telemetry. */
object ModelUpdateScheduler {
    const val UNIQUE_WORK_NAME = "safe_mobile_research_ml_weekly"
    fun ensureWeekly(context: Context) {
        val work = PeriodicWorkRequestBuilder<ModelUpdateWorker>(7, TimeUnit.DAYS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            UNIQUE_WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, work)
    }
}
