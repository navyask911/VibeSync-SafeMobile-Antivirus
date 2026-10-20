package com.vibesync.antivirus.core.observer
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

class PackageInstallReceiver : BroadcastReceiver() {
 override fun onReceive(context: Context, intent: Intent) {
  val preferences = context.applicationContext.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
  if (!preferences.getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)) return
  val packageName = intent.data?.schemeSpecificPart ?: return
  val pendingResult = goAsync()
  val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  scope.launch {
   try { (context.applicationContext as SafeMobileApp).repository.scanInstalledPackage(packageName) }
   finally { pendingResult.finish(); scope.cancel() }
  }
 }
}
