package com.vibesync.antivirus
import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.ads.MobileAds
import com.google.android.play.core.appupdate.AppUpdateManager
import com.google.android.play.core.appupdate.AppUpdateManagerFactory
import com.google.android.play.core.appupdate.AppUpdateOptions
import com.google.android.play.core.install.InstallState
import com.google.android.play.core.install.InstallStateUpdatedListener
import com.google.android.play.core.install.model.AppUpdateType
import com.google.android.play.core.install.model.InstallStatus
import com.google.android.play.core.install.model.UpdateAvailability
import com.vibesync.antivirus.ads.ConsentManager
import com.vibesync.antivirus.presentation.SafeMobileScreen
import com.vibesync.antivirus.presentation.SafeMobileTheme

class MainActivity : ComponentActivity() {
 private var adsReady by mutableStateOf(false)
 private lateinit var updateManager: AppUpdateManager
 private var checkingUpdate = false
 private val updateLauncher = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result: ActivityResult ->
  if (result.resultCode == Activity.RESULT_OK) checkForUpdate()
  else checkingUpdate = false
 }
 private val installListener = InstallStateUpdatedListener { state: InstallState ->
  if (state.installStatus() == InstallStatus.DOWNLOADED) updateManager.completeUpdate()
 }
 override fun onCreate(savedInstanceState: Bundle?) {
  super.onCreate(savedInstanceState)
  updateManager = AppUpdateManagerFactory.create(this)
  updateManager.registerListener(installListener)
  setContent {
   SafeMobileTheme {
    SafeMobileScreen(repository = (application as SafeMobileApp).repository, adsEnabled = adsReady)
   }
  }
  ConsentManager.requestConsent(this) { canRequestAds ->
   if (canRequestAds) {
    MobileAds.initialize(this) { adsReady = true }
   }
  }
  checkForUpdate()
 }
 override fun onResume() {
  super.onResume()
  if (!::updateManager.isInitialized) return
  updateManager.appUpdateInfo.addOnSuccessListener { info ->
   if (info.installStatus() == InstallStatus.DOWNLOADED) {
    updateManager.completeUpdate()
   } else if (info.updateAvailability() == UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {
    runCatching {
     updateManager.startUpdateFlowForResult(info, updateLauncher,
      AppUpdateOptions.newBuilder(AppUpdateType.IMMEDIATE).build())
    }
   } else {
    checkForUpdate()
   }
  }
 }
 private fun checkForUpdate() {
  if (!::updateManager.isInitialized || checkingUpdate || isFinishing) return
  checkingUpdate = true
  updateManager.appUpdateInfo.addOnCompleteListener { task ->
   checkingUpdate = false
   if (!task.isSuccessful) return@addOnCompleteListener
   val info = task.result
   if (info.updateAvailability() != UpdateAvailability.UPDATE_AVAILABLE) return@addOnCompleteListener
   val staleDays = info.clientVersionStalenessDays() ?: 0
   val preferImmediate = info.updatePriority() >= 4 || staleDays >= 7
   val type = if (preferImmediate && info.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)) AppUpdateType.IMMEDIATE else AppUpdateType.FLEXIBLE
   if (info.isUpdateTypeAllowed(type)) {
    updateManager.startUpdateFlowForResult(info, updateLauncher, AppUpdateOptions.newBuilder(type).build())
   }
  }
 }
 override fun onDestroy() {
  if (::updateManager.isInitialized) updateManager.unregisterListener(installListener)
  super.onDestroy()
 }
}
