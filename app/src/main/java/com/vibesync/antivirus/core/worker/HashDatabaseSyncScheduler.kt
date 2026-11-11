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
import androidx.lifecycle.Observer
import com.vibesync.antivirus.BuildConfig
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
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

    fun initialSyncPending(context: Context): Flow<Boolean> = callbackFlow {
        val workInfos = WorkManager.getInstance(context)
            .getWorkInfosForUniqueWorkLiveData(INITIAL_WORK_NAME)
        val observer = Observer<List<WorkInfo>> { infos ->
            trySend(infos.orEmpty().any {
                it.state == WorkInfo.State.ENQUEUED ||
                    it.state == WorkInfo.State.RUNNING ||
                    it.state == WorkInfo.State.BLOCKED
            })
        }
        workInfos.observeForever(observer)
        awaitClose { workInfos.removeObserver(observer) }
    }.distinctUntilChanged()

    private fun networkConstraints() = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.CONNECTED)
        .build()
}
