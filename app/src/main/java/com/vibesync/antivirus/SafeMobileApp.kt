package com.vibesync.antivirus
import android.app.Application
import androidx.room.Room
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.worker.DeepScanWorker
import com.vibesync.antivirus.core.worker.LocalDefinitionLoader
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.data.repository.ThreatIntelligenceRepository
import com.vibesync.antivirus.core.worker.ThreatFeedSyncScheduler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.concurrent.TimeUnit
class SafeMobileApp : Application() {
 lateinit var database: ThreatDatabase
  private set
 lateinit var repository: ThreatRepository
  private set
 private val appScope=CoroutineScope(SupervisorJob()+Dispatchers.IO)
 override fun onCreate() {
  super.onCreate()
  database=Room.databaseBuilder(this,ThreatDatabase::class.java,"safe_mobile_threats.db")
   .addMigrations(ThreatDatabase.MIGRATION_1_2, ThreatDatabase.MIGRATION_2_3, ThreatDatabase.MIGRATION_3_4, ThreatDatabase.MIGRATION_4_5, ThreatDatabase.MIGRATION_5_6, ThreatDatabase.MIGRATION_6_7)
   .build()
  val hashStore=EncryptedHashStore(this)
  val loader=LocalDefinitionLoader(this,database.threatDao(),hashStore)
  val intelligence=ThreatIntelligenceRepository(database.malwareHashDao(),database.threatFeedSyncStateDao())
  val scanner=PackageScanner(this,database.threatDao(),hashStore,HashCalculator(),threatIntelligenceRepository=intelligence)
  repository=ThreatRepository(this,database,scanner,loader,intelligence)
  ThreatFeedSyncScheduler.ensurePeriodic(this)
  appScope.launch { runCatching { loader.importBundledIfEmpty() } }
  if (getSharedPreferences(PRIVACY_PREFS, MODE_PRIVATE).getBoolean(PRIVACY_ACKNOWLEDGED, false)) {
   scheduleMaintenanceSweep()
  }
 }
 fun scheduleMaintenanceSweep() {
  val request=PeriodicWorkRequestBuilder<DeepScanWorker>(6,TimeUnit.HOURS)
   .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build()).build()
  WorkManager.getInstance(this).enqueueUniquePeriodicWork(
   DeepScanWorker.UNIQUE_NAME,ExistingPeriodicWorkPolicy.UPDATE,request
  )
 }
 override fun onTerminate() { appScope.cancel(); super.onTerminate() }
 companion object {
  const val SECURITY_PREFS = "safe_mobile_security_settings"
  const val KEY_DOWNLOAD_SENTINEL_ENABLED = "download_sentinel_enabled"
  const val KEY_STRICT_MODE = "download_sentinel_strict_mode"
  const val PRIVACY_PREFS = "safe_mobile_privacy"
  const val PRIVACY_ACKNOWLEDGED = "acknowledged"
 }
}
