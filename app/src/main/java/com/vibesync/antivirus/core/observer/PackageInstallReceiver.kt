package com.vibesync.antivirus.core.observer
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.security.InstallSourceCategory
import com.vibesync.antivirus.core.security.InstallSourceVerifier
import com.vibesync.antivirus.core.worker.MultiLayerScanWorker
import com.vibesync.antivirus.data.local.SecurityIncidentEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.UUID

class PackageInstallReceiver : BroadcastReceiver() {
 override fun onReceive(context: Context, intent: Intent) {
  if (intent.action != Intent.ACTION_PACKAGE_ADDED && intent.action != Intent.ACTION_PACKAGE_REPLACED) return
  val appContext=context.applicationContext
  if (!appContext.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS,Context.MODE_PRIVATE).getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED,false)) return
  val name=intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
  if(name==appContext.packageName) return
  val update=intent.action==Intent.ACTION_PACKAGE_REPLACED || intent.getBooleanExtra(Intent.EXTRA_REPLACING,false)
  val pending=goAsync()
  val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO)
  scope.launch {
   try {
    val app=appContext as? SafeMobileApp ?: return@launch
    val source=InstallSourceVerifier(appContext).inspect(name)
    val category=when(source.category) {
     InstallSourceCategory.PLAY_STORE -> "PLAY_STORE"
     InstallSourceCategory.EXTERNAL -> "EXTERNAL"
     InstallSourceCategory.UNKNOWN -> "UNKNOWN"
    }
    val eventId=UUID.randomUUID().toString()
    val label=resolveLabel(appContext,name)
    val detail="Category="+category+"; initiating="+(source.initiatingPackageName ?: "unknown")+
     "; installing="+(source.installingPackageName ?: "unknown")+
     "; originating="+(source.originatingPackageName ?: "not exposed by Android")
    app.database.securityIncidentDao().insert(SecurityIncidentEntity(
     eventId=eventId,occurredAt=System.currentTimeMillis(),
     eventKind=if(update) "PACKAGE_UPDATED" else "PACKAGE_INSTALL",
     installerPackage=source.initiatingPackageName ?: source.installingPackageName,
     sourcePackage=name,reason=detail,
     actionTaken=if(source.needsReview && !update) "INSTALL_SOURCE_ALERT" else "SOURCE_RECORDED",
     status=category
    ))
    if(source.needsReview && !update) InstallSourceNotifier.notify(appContext,label,source.sourceLabel,eventId)
    val request=OneTimeWorkRequestBuilder<MultiLayerScanWorker>().setInputData(
     Data.Builder().putString(MultiLayerScanWorker.KEY_PACKAGE_NAME,name)
      .putString(MultiLayerScanWorker.KEY_EVENT_ID,eventId).build()
    ).build()
    WorkManager.getInstance(appContext).enqueueUniqueWork("multi_layer_install_scan_"+name,ExistingWorkPolicy.REPLACE,request)
   } catch (_: Exception) {
    // Best-effort broadcast handler; do not crash the package installer.
   } finally { pending.finish(); scope.cancel() }
  }
 }
 private fun resolveLabel(context: Context,name: String): String = try {
  val pm=context.packageManager
  val info=if(android.os.Build.VERSION.SDK_INT>=android.os.Build.VERSION_CODES.TIRAMISU) {
   pm.getApplicationInfo(name,PackageManager.ApplicationInfoFlags.of(0L))
  } else {
   @Suppress("DEPRECATION")
   pm.getApplicationInfo(name,0)
  }
  pm.getApplicationLabel(info).toString()
 } catch (_: Exception) { name }
}
