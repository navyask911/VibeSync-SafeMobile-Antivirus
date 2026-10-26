package com.vibesync.antivirus

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import com.vibesync.antivirus.core.observer.PackageInstallReceiver
import android.util.Log
import androidx.room.Room
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.engine.BundledYaraEngine
import com.vibesync.antivirus.core.hashdb.HashDatabaseManager
import com.vibesync.antivirus.core.security.DeviceOwnerManager
import com.vibesync.antivirus.core.posture.DevicePostureMonitor
import com.vibesync.antivirus.core.posture.DevicePostureRepository
import com.vibesync.antivirus.core.worker.DeepScanWorker
import com.vibesync.antivirus.core.worker.HashDatabaseSyncScheduler
import com.vibesync.antivirus.core.worker.LocalDefinitionLoader
import com.vibesync.antivirus.core.worker.ThreatFeedSyncScheduler
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.repository.ThreatIntelligenceRepository
import com.vibesync.antivirus.data.repository.ThreatRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit

class SafeMobileApp : Application() {
    lateinit var database: ThreatDatabase
        private set
    lateinit var hashDatabaseManager: HashDatabaseManager
        private set
    lateinit var repository: ThreatRepository
        private set

    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var runtimePackageInstallReceiver: BroadcastReceiver? = null
    val devicePostureRepository by lazy { DevicePostureRepository(this) }

    override fun onCreate() {
        super.onCreate()
        // Manifest-only implicit PACKAGE_ADDED is not delivered on Android 8+.
        // Register while SafeMobile is running; OEM process shutdown may still limit delivery.
        val packageFilter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }
        runCatching {
            val receiver = PackageInstallReceiver()
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(receiver, packageFilter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(receiver, packageFilter)
            }
            runtimePackageInstallReceiver = receiver
            Log.d("SafeMobileScan", "Runtime post-install receiver registered")
        }.onFailure { Log.w("SafeMobileScan", "Unable to register runtime package receiver", it) }

        // Only ~2 KiB of signed-APK text is loaded; all APK scanning stays on Dispatchers.IO.
        BundledYaraEngine.initialize(assets)
        runCatching { DeviceOwnerManager(this).applyEnterpriseDefaults() }
        database = Room.databaseBuilder(this, ThreatDatabase::class.java, "safe_mobile_threats.db")
            .addMigrations(
                ThreatDatabase.MIGRATION_1_2, ThreatDatabase.MIGRATION_2_3,
                ThreatDatabase.MIGRATION_3_4, ThreatDatabase.MIGRATION_4_5,
                ThreatDatabase.MIGRATION_5_6, ThreatDatabase.MIGRATION_6_7,
                ThreatDatabase.MIGRATION_7_8, ThreatDatabase.MIGRATION_8_9
            )
            .build()
        hashDatabaseManager = HashDatabaseManager(this, database)
        val hashStore = EncryptedHashStore(this)
        val loader = LocalDefinitionLoader(this, database.threatDao(), hashStore)
        val intelligence = ThreatIntelligenceRepository(
            database.malwareHashDao(), database.threatFeedSyncStateDao()
        )
        val scanner = PackageScanner(
            this, database.threatDao(), hashStore, HashCalculator(),
            threatIntelligenceRepository = intelligence,
            hashDatabaseManager = hashDatabaseManager
        )
        repository = ThreatRepository(
            this, database, scanner, loader, intelligence,
            hashDatabaseManager = hashDatabaseManager
        )

        if (BuildConfig.OPTIONAL_FEED_ENABLED) ThreatFeedSyncScheduler.ensurePeriodic(this)
        HashDatabaseSyncScheduler.ensurePeriodic(this)
        val syncPrefs = getSharedPreferences(HASH_DATABASE_SYNC_PREFS, MODE_PRIVATE)
        if (!syncPrefs.getBoolean(KEY_INITIAL_HASH_SYNC_REQUESTED, false)) {
            HashDatabaseSyncScheduler.enqueueInitial(this)
            syncPrefs.edit().putBoolean(KEY_INITIAL_HASH_SYNC_REQUESTED, true).apply()
        }

        appScope.launch {
            runCatching { hashDatabaseManager.restoreActiveDatabase() }
                .onFailure {
                    Log.e("SafeMobileApp", "Could not restore signed hash database; local matching remains inactive.", it)
                }
            runCatching { loader.importBundledIfEmpty() }
                .onFailure { Log.e("SafeMobileApp", "Local threat definitions could not be loaded.", it) }
        }

        if (getSharedPreferences(PRIVACY_PREFS, MODE_PRIVATE)
                .getBoolean(PRIVACY_ACKNOWLEDGED, false)
        ) {
            scheduleMaintenanceSweep()
        }
    }

    fun scheduleMaintenanceSweep() {
        DevicePostureMonitor.ensureScheduled(this)
        val request = PeriodicWorkRequestBuilder<DeepScanWorker>(6, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
            .build()
        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            DeepScanWorker.UNIQUE_NAME, ExistingPeriodicWorkPolicy.UPDATE, request
        )
    }

    override fun onTerminate() {
        runtimePackageInstallReceiver?.let { receiver -> runCatching { unregisterReceiver(receiver) } }
        runtimePackageInstallReceiver = null
        appScope.cancel()
        super.onTerminate()
    }

    companion object {
        const val SECURITY_PREFS = "safe_mobile_security_settings"
        const val KEY_VOICE_ALERTS_ENABLED = "voice_alerts_enabled"
        const val KEY_SECURITY_ALERTS_ENABLED = "security_alerts_enabled"
        const val KEY_DOWNLOAD_SENTINEL_ENABLED = "download_sentinel_enabled"
        const val KEY_STRICT_MODE = "download_sentinel_strict_mode"
        const val PRIVACY_PREFS = "safe_mobile_privacy"
        const val PRIVACY_ACKNOWLEDGED = "acknowledged"
        const val HASH_DATABASE_SYNC_PREFS = "safe_mobile_hash_sync_bootstrap"
        const val KEY_INITIAL_HASH_SYNC_REQUESTED = "initial_hash_sync_requested"
    }
}

