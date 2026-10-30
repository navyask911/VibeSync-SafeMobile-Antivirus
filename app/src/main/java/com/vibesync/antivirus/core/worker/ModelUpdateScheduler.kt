package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Downloads research candidates only, never scans remotely or bypasses validation.
 * Free baseline is every seven days; device-local Pro enables optional 24-hour
 * research staging but does NOT turn the unvalidated model into malware protection.
 */
object ModelUpdateScheduler {
    const val UNIQUE_WORK_NAME = "safe_mobile_research_ml_weekly"
    fun ensureWeekly(context: Context) = ensureCadence(context, pro = false)

    fun ensureCadence(context: Context, pro: Boolean) {
        val period = if (pro) 1L else 7L
        val work = PeriodicWorkRequestBuilder<ModelUpdateWorker>(period, TimeUnit.DAYS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .build()
        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            UNIQUE_WORK_NAME, ExistingPeriodicWorkPolicy.UPDATE, work)
    }
}
