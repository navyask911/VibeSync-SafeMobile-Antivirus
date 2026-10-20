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
  database=Room.databaseBuilder(this,ThreatDatabase::class.java,"safe_mobile_threats.db").build()
  val hashStore=EncryptedHashStore(this)
  val loader=LocalDefinitionLoader(this,database.threatDao(),hashStore)
  val scanner=PackageScanner(this,database.threatDao(),hashStore,HashCalculator())
  repository=ThreatRepository(this,database,scanner,loader)
  appScope.launch { runCatching { loader.importBundledIfEmpty() } }
  if (getSharedPreferences(PRIVACY_PREFS, MODE_PRIVATE).getBoolean(PRIVACY_ACKNOWLEDGED, false)) {
   scheduleMaintenanceSweep()
  }
 }
 fun scheduleMaintenanceSweep() {
  val request=PeriodicWorkRequestBuilder<DeepScanWorker>(12,TimeUnit.HOURS)
   .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build()).build()
  WorkManager.getInstance(this).enqueueUniquePeriodicWork(
   DeepScanWorker.UNIQUE_NAME,ExistingPeriodicWorkPolicy.KEEP,request
  )
 }
 override fun onTerminate() { appScope.cancel(); super.onTerminate() }
 companion object {
  const val PRIVACY_PREFS = "safe_mobile_privacy"
  const val PRIVACY_ACKNOWLEDGED = "acknowledged"
 }
}
