package com.vibesync.antivirus.core.security

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import com.vibesync.antivirus.R

/** Thin wrapper around the consumer Device Administrator APIs supported by Android. */
class DeviceAdminManager(context: Context) {
    private val appContext = context.applicationContext
    private val policies = appContext.getSystemService(DevicePolicyManager::class.java)
    private val component = ComponentName(appContext, AntivirusAdminReceiver::class.java)

    fun isActive(): Boolean = runCatching { policies?.isAdminActive(component) == true }.getOrDefault(false)

    fun enableIntent(): Intent =
        Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN).apply {
            putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, component)
            putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, appContext.getString(R.string.device_admin_explanation))
        }

    @Suppress("DEPRECATION")
    fun applyMinimumPasswordLength(length: Int = 8): Boolean {
        if (!isActive() || length !in 6..16) return false
        return try {
            val manager = policies ?: return false
            manager.setPasswordQuality(component, DevicePolicyManager.PASSWORD_QUALITY_COMPLEX)
            manager.setPasswordMinimumLength(component, length)
            true
        } catch (_: SecurityException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: IllegalStateException) {
            // Modern Android can reject legacy password policy combinations for target-SDK 30+ apps.
            false
        }
    }

    fun forceLock(): Boolean {
        if (!isActive()) return false
        return try {
            val manager = policies ?: return false
            manager.lockNow()
            true
        } catch (_: SecurityException) {
            false
        }
    }
}
