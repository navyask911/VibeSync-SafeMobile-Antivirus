package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.getWorkInfosForUniqueWorkFlow
import com.vibesync.antivirus.BuildConfig
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import java.util.concurrent.TimeUnit

object HashDatabaseSyncScheduler {
    const val INITIAL_WORK_NAME = "safe_mobile_signed_hash_database_initial"
    private const val UNIQUE_PERIODIC = "safe_mobile_signed_hash_database_periodic"
    private const val UNIQUE_NOW = "safe_mobile_signed_hash_database_manual"

    fun ensurePeriodic(context: Context) {
        if (!BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED) return
        val request = PeriodicWorkRequestBuilder<HashDatabaseSyncWorker>(6, TimeUnit.HOURS)
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            UNIQUE_PERIODIC, ExistingPeriodicWorkPolicy.UPDATE, request
        )
    }

    fun enqueueInitial(context: Context) {
        if (!BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED) return
        val request = OneTimeWorkRequestBuilder<HashDatabaseSyncWorker>()
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            INITIAL_WORK_NAME, ExistingWorkPolicy.KEEP, request
        )
    }

    fun enqueueNow(context: Context) {
        if (!BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED) return
        val request = OneTimeWorkRequestBuilder<HashDatabaseSyncWorker>()
            .setConstraints(networkConstraints())
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(
            UNIQUE_NOW, ExistingWorkPolicy.REPLACE, request
        )
    }

    fun initialSyncPending(context: Context): Flow<Boolean> =
        WorkManager.getInstance(context)
            .getWorkInfosForUniqueWorkFlow(INITIAL_WORK_NAME)
            .map { workInfos ->
                workInfos.any {
                    it.state == WorkInfo.State.ENQUEUED ||
                        it.state == WorkInfo.State.RUNNING ||
                        it.state == WorkInfo.State.BLOCKED
                }
            }

    private fun networkConstraints() = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .build()
}
