package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.core.hashdb.HashDatabaseConfigStore
import java.util.concurrent.TimeUnit

object HashDatabaseSyncScheduler {
    private const val UNIQUE_PERIODIC = "safe_mobile_signed_hash_database_periodic"
    private const val UNIQUE_NOW = "safe_mobile_signed_hash_database_manual"

    fun ensurePeriodic(context: Context) {
        if (!BuildConfig.OPTIONAL_FEED_ENABLED || !BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED) return
        val config = runCatching { HashDatabaseConfigStore(context).read() }.getOrNull() ?: return
        if (!config.enabled || config.url.isBlank()) return
        val request = PeriodicWorkRequestBuilder<HashDatabaseSyncWorker>(12, TimeUnit.HOURS)
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            UNIQUE_PERIODIC, ExistingPeriodicWorkPolicy.UPDATE, request
        )
    }

    fun enqueueNow(context: Context) {
        if (!BuildConfig.OPTIONAL_FEED_ENABLED || !BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED) return
        val request = OneTimeWorkRequestBuilder<HashDatabaseSyncWorker>()
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            UNIQUE_NOW, androidx.work.ExistingWorkPolicy.REPLACE, request
        )
    }

    private fun networkConstraints() = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .setRequiresBatteryNotLow(true)
        .build()
}
