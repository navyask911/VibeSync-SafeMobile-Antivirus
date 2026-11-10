package com.vibesync.antivirus.core.security

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import com.vibesync.antivirus.R

/**
 * Consumer Device Administrator activation flow.
 *
 * This is intentionally separate from DeviceOwnerManager. A standard admin cannot enforce
 * device-owner restrictions such as blocking unknown-source installation.
 */
class DeviceAdminManager(context: Context) {
    private val appContext = context.applicationContext
    private val policyManager = appContext.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
    private val component = ComponentName(appContext, AdminReceiver::class.java)

    fun isAdminActive(): Boolean = runCatching {
        policyManager.isAdminActive(component)
    }.getOrDefault(false)

    /**
     * Launches Android's explicit user-consent screen. Using the application context plus
     * NEW_TASK avoids a silent no-op when Compose supplies a ContextWrapper instead of Activity.
     */
    fun requestAdminPermission() {
        if (isAdminActive()) return
        val intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, component)
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, appContext.getString(R.string.device_admin_explanation))
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        appContext.startActivity(intent)
    }

    /** Invokes Android's confirmation flow; actual state is refreshed when the app resumes. */
    fun removeAdmin() {
        if (isAdminActive()) policyManager.removeActiveAdmin(component)
    }
}
