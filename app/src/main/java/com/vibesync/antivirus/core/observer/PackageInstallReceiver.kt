package com.vibesync.antivirus.core.observer
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.util.Log
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
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

/**
 * System package broadcasts arrive after Android has installed/replaced a package. This receiver
 * queues offline post-install analysis; it is not a pre-install interception point.
 */
class PackageInstallReceiver : BroadcastReceiver() {
 override fun onReceive(context: Context, intent: Intent) {
  if (intent.action != Intent.ACTION_PACKAGE_ADDED && intent.action != Intent.ACTION_PACKAGE_REPLACED) return
  val appContext=context.applicationContext
  val packageName=intent.data?.schemeSpecificPart?.takeIf { it.isNotBlank() } ?: return
  Log.d("SafeMobileScan", "New package installed: $packageName")
  if (!appContext.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS,Context.MODE_PRIVATE).getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED,false)) {
   Log.d("SafeMobileScan", "Post-install scan skipped: privacy disclosure not acknowledged.")
   return
  }
  if(packageName==appContext.packageName) return
  val update=intent.action==Intent.ACTION_PACKAGE_REPLACED || intent.getBooleanExtra(Intent.EXTRA_REPLACING,false)
  val pending=goAsync()
  val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO)
  scope.launch {
   try {
    val app=appContext as? SafeMobileApp ?: return@launch
    val source=InstallSourceVerifier(appContext).inspect(packageName)
    val privateTextStore=EncryptedHashStore(appContext)
    val category=when(source.category) {
     InstallSourceCategory.PLAY_STORE -> "PLAY_STORE"
     InstallSourceCategory.EXTERNAL -> "EXTERNAL"
     InstallSourceCategory.UNKNOWN -> "UNKNOWN"
    }
    val eventId=UUID.randomUUID().toString()
    val label=resolveLabel(appContext,packageName)
    val detail="Category="+category+"; initiating="+(source.initiatingPackageName ?: "unknown")+
     "; installing="+(source.installingPackageName ?: "unknown")+
     "; originating="+(source.originatingPackageName ?: "not exposed by Android")
    app.database.securityIncidentDao().insert(SecurityIncidentEntity(
     eventId=eventId,occurredAt=System.currentTimeMillis(),
     eventKind=if(update) "PACKAGE_UPDATED" else "PACKAGE_INSTALL",
     installerPackage=(source.initiatingPackageName ?: source.installingPackageName)?.let { privateTextStore.protectPrivateText(it, "incident-installer") },
     sourcePackage=privateTextStore.protectPrivateText(packageName, "incident-source"),
     reason=privateTextStore.protectPrivateText(detail.take(1024), "incident-reason"),
     actionTaken=if(source.needsReview && !update) "INSTALL_SOURCE_ALERT" else "SOURCE_RECORDED",
     status=category
    ))
    if(source.needsReview && !update) InstallSourceNotifier.notify(appContext,label,source.sourceLabel,eventId)
    // WorkManager runs the local scan off the broadcast thread; no network constraint or upload is used.
    val request=OneTimeWorkRequestBuilder<MultiLayerScanWorker>().setInputData(
     Data.Builder().putString(MultiLayerScanWorker.KEY_PACKAGE_NAME,packageName)
      .putString(MultiLayerScanWorker.KEY_EVENT_ID,eventId).build()
    ).build()
    WorkManager.getInstance(appContext).enqueueUniqueWork("multi_layer_install_scan_"+packageName,ExistingWorkPolicy.REPLACE,request)
   } catch (_: Exception) {
    // Best-effort broadcast handler; do not crash the package installer.
   } finally { pending.finish(); scope.cancel() }
  }
 }
 private fun resolveLabel(context: Context,packageName: String): String = try {
  val pm=context.packageManager
  val info=if(android.os.Build.VERSION.SDK_INT>=android.os.Build.VERSION_CODES.TIRAMISU) {
   pm.getApplicationInfo(packageName,PackageManager.ApplicationInfoFlags.of(0L))
  } else {
   @Suppress("DEPRECATION")
   pm.getApplicationInfo(packageName,0)
  }
  pm.getApplicationLabel(info).toString()
 } catch (_: Exception) { packageName }
}
