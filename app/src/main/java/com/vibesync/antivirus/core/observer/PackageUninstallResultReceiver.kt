package com.vibesync.antivirus.core.observer
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.data.local.SecurityIncidentEntity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.util.UUID
/** Persists actual PackageInstaller callback state; an uninstall request isn't assumed successful. */
class PackageUninstallResultReceiver : BroadcastReceiver() {
 override fun onReceive(context: Context,intent: Intent?) {
  if (intent == null) return
  val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE)
  val target = intent.getStringExtra(EXTRA_TARGET_PACKAGE)
  val eventId = intent.getStringExtra(EXTRA_EVENT_ID)
  val pending = goAsync()
  val scope = CoroutineScope(SupervisorJob()+Dispatchers.IO)
  scope.launch {
   try {
    val app = context.applicationContext as? SafeMobileApp ?: return@launch
    val name = if (status == PackageInstaller.STATUS_SUCCESS) "SUCCESS" else "STATUS_" + status
    val dao = app.database.securityIncidentDao()
    val previous = eventId?.let { dao.findById(it) }
    if (previous != null) dao.updateAssessment(previous.eventId,previous.sha256Hash,
     (previous.reason + "\nDevice Owner uninstall callback: " + name).take(4000),
     (previous.actionTaken + "; UNINSTALL_" + name).take(500),(previous.status + "|UNINSTALL_" + name).take(200))
    else dao.insert(SecurityIncidentEntity(UUID.randomUUID().toString(),System.currentTimeMillis(),"ENTERPRISE_UNINSTALL_RESULT",
     sourcePackage=target,reason="Device Owner PackageInstaller callback: " + name,actionTaken="UNINSTALL_CALLBACK",status=name))
   } catch (_: Exception) { } finally { pending.finish(); scope.cancel() }
  }
 }
 companion object {
  const val EXTRA_TARGET_PACKAGE = "enterprise_uninstall.target_package"
  const val EXTRA_EVENT_ID = "enterprise_uninstall.event_id"
 }
}
