package com.vibesync.antivirus.core.security
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.os.UserManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
/** Privileged controls are inert unless Android actually provisioned this app as Device Owner. */
class DeviceOwnerManager(context: Context) {
 private val app = context.applicationContext
 private val dpm = app.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
 private val admin = ComponentName(app,AdminReceiver::class.java)
 private val ownerState = MutableStateFlow(isOwner())
 val isDeviceOwner: StateFlow<Boolean> = ownerState.asStateFlow()
 fun refreshState() { val owner = isOwner(); ownerState.value = owner; if (owner) applyEnterpriseDefaults() }
 fun applyEnterpriseDefaults(): Boolean {
  if (!isOwner()) return false
  return runCatching { dpm.addUserRestriction(admin,UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES); true }.getOrDefault(false)
 }
 private fun isOwner() = runCatching { dpm.isDeviceOwnerApp(app.packageName) }.getOrDefault(false)
 companion object {
  const val PREFS_NAME = "safe_mobile_enterprise"
  const val KEY_AUTOMATIC_RESPONSE = "automatic_response_confirmed_hash_matches"
  const val ACTION_UNINSTALL_STATUS = "com.vibesync.antivirus.ENTERPRISE_UNINSTALL_STATUS"
  const val MIN_SCORE = 0.8f
 }
}

