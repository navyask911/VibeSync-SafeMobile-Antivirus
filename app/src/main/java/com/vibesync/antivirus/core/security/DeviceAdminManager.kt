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
    private val component = ComponentName(appContext.packageName, AdminReceiver::class.java.name)

    fun isAdminActive(): Boolean = runCatching {
        policyManager.isAdminActive(component)
    }.getOrDefault(false)

    /**
     * Build the explicit system activation request so the exact action and component can
     * be verified independently of launching Android's protected confirmation activity.
     */
    fun activationIntent(): Intent = Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
        putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, component)
        putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, appContext.getString(R.string.security_guard_admin_consent_body))
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }

    /** Launches Android's user-consent screen; activation state is refreshed on resume. */
    fun requestAdminPermission() {
        if (isAdminActive()) return
        appContext.startActivity(activationIntent())
    }

    /** Invokes Android's confirmation flow; actual state is refreshed when the app resumes. */
    fun removeAdmin() {
        if (isAdminActive()) policyManager.removeActiveAdmin(component)
    }
}
