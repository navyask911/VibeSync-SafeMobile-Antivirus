package com.vibesync.antivirus.core.posture

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

/** Offline six-hour checks. WorkManager persists jobs across reboot; Android may defer execution. */
object DevicePostureMonitor {
    const val PREFS = "safe_mobile_device_posture_settings"
    const val PERIODIC_WORK = "safe_mobile_device_posture_periodic"
    const val IMMEDIATE_WORK = "safe_mobile_device_posture_now"
    private const val ENABLED = "monitor_enabled"

    fun isEnabled(context: Context) = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(ENABLED, true)
    fun ensureScheduled(context: Context) {
        if (!isEnabled(context)) return
        val request = PeriodicWorkRequestBuilder<DevicePostureWorker>(6, TimeUnit.HOURS)
            .setInitialDelay(6, TimeUnit.HOURS)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES).build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.KEEP, request)
        enqueueNow(context)
    }
    fun enqueueNow(context: Context) {
        if (!isEnabled(context)) return
        val request = OneTimeWorkRequestBuilder<DevicePostureWorker>()
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES).build()
        WorkManager.getInstance(context).enqueueUniqueWork(IMMEDIATE_WORK, ExistingWorkPolicy.KEEP, request)
    }
    fun setEnabled(context: Context, enabled: Boolean) {
        check(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(ENABLED, enabled).commit())
        if (enabled) ensureScheduled(context) else {
            WorkManager.getInstance(context).cancelUniqueWork(PERIODIC_WORK)
            WorkManager.getInstance(context).cancelUniqueWork(IMMEDIATE_WORK)
        }
    }
}
