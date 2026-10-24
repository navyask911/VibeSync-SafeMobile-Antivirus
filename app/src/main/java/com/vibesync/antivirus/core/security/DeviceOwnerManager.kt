package com.vibesync.antivirus.core.security
import android.app.PendingIntent
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.UserManager
import com.vibesync.antivirus.core.engine.ThreatVerdict
import com.vibesync.antivirus.core.observer.PackageUninstallResultReceiver
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
/** Privileged controls are inert unless Android actually provisioned this app as Device Owner. */
class DeviceOwnerManager(context: Context) {
 private val app = context.applicationContext
 private val dpm = app.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
 private val admin = ComponentName(app,AntivirusAdminReceiver::class.java)
 private val prefs = app.getSharedPreferences(PREFS_NAME,Context.MODE_PRIVATE)
 private val ownerState = MutableStateFlow(isOwner())
 val isDeviceOwner: StateFlow<Boolean> = ownerState.asStateFlow()
 fun refreshState() { val owner = isOwner(); ownerState.value = owner; if (owner) applyEnterpriseDefaults() }
 fun applyEnterpriseDefaults(): Boolean {
  if (!isOwner()) return false
  return runCatching { dpm.addUserRestriction(admin,UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES); true }.getOrDefault(false)
 }
 fun isAutomaticResponseConfigured() = prefs.getBoolean(KEY_AUTOMATIC_RESPONSE,false)
 fun isAutomaticResponseEnabled() = isOwner() && isAutomaticResponseConfigured()
 fun setAutomaticResponseEnabled(enabled: Boolean): Boolean {
  if (enabled && !isOwner()) return false
  prefs.edit().putBoolean(KEY_AUTOMATIC_RESPONSE,enabled).apply()
  return true
 }
 fun hideConfirmedThreat(packageName: String, verdict: ThreatVerdict): Boolean {
  if (!eligible(packageName,verdict)) return false
  return runCatching { dpm.setApplicationHidden(admin,packageName,true) }.getOrDefault(false)
 }
 fun requestConfirmedThreatUninstall(packageName: String, verdict: ThreatVerdict, eventId: String): Boolean {
  if (!eligible(packageName,verdict)) return false
  return runCatching {
   val callback = Intent(app,PackageUninstallResultReceiver::class.java)
    .setAction(ACTION_UNINSTALL_STATUS)
    .putExtra(PackageUninstallResultReceiver.EXTRA_TARGET_PACKAGE,packageName)
    .putExtra(PackageUninstallResultReceiver.EXTRA_EVENT_ID,eventId)
   var flags = PendingIntent.FLAG_UPDATE_CURRENT
   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) flags = flags or PendingIntent.FLAG_MUTABLE
   val pending = PendingIntent.getBroadcast(app,packageName.hashCode(),callback,flags)
   app.packageManager.packageInstaller.uninstall(packageName,pending.intentSender)
   true
  }.getOrDefault(false)
 }
 private fun eligible(name: String, verdict: ThreatVerdict): Boolean {
  if (!isAutomaticResponseEnabled() || name.isBlank() || name == app.packageName) return false
  if (!verdict.isMalware || verdict.riskScore <= MIN_SCORE) return false
  val info = try {
   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) app.packageManager.getApplicationInfo(name,PackageManager.ApplicationInfoFlags.of(0L))
   else {
    @Suppress("DEPRECATION")
    app.packageManager.getApplicationInfo(name,0)
   }
  } catch (_: PackageManager.NameNotFoundException) { return false } catch (_: SecurityException) { return false }
  return info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
 }
 private fun isOwner() = runCatching { dpm.isDeviceOwnerApp(app.packageName) }.getOrDefault(false)
 companion object {
  const val PREFS_NAME = "safe_mobile_enterprise"
  const val KEY_AUTOMATIC_RESPONSE = "automatic_response_confirmed_hash_matches"
  const val ACTION_UNINSTALL_STATUS = "com.vibesync.antivirus.ENTERPRISE_UNINSTALL_STATUS"
  const val MIN_SCORE = 0.8f
 }
}
