package com.vibesync.antivirus.core.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.view.accessibility.AccessibilityManager

/** Reads enabled services/admins only. Does not request accessibility or device-admin privileges. */
object DeviceSecurityInspector {
    private const val PREFS = "safe_mobile_play_protect_report"
    fun reportPlayProtect(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putBoolean("enabled", enabled).putLong("reported_at", System.currentTimeMillis()).apply()
    }
    fun inspect(context: Context, databaseUpdatedAt: Long?): DeviceSecuritySignals {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val age = System.currentTimeMillis() - prefs.getLong("reported_at", 0L)
        val reportedPlayProtect = if (age in 0 until DeviceSecurityScore.FRESHNESS_MS && prefs.contains("enabled"))
            prefs.getBoolean("enabled", false) else null
        val accessibility = runCatching {
            val manager = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
                ?: return@runCatching null
            manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                .mapNotNull { it.resolveInfo?.serviceInfo?.applicationInfo }
                .filter { isNonSystem(it.flags) }.map { it.packageName }.distinct().size
        }.getOrNull()
        val admins = runCatching {
            val manager = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
                ?: return@runCatching null
            manager.activeAdmins.orEmpty().map { component ->
                @Suppress("DEPRECATION")
                context.packageManager.getApplicationInfo(component.packageName, 0)
            }.filter { isNonSystem(it.flags) }.map { it.packageName }.distinct().size
        }.getOrNull()
        return DeviceSecuritySignals(reportedPlayProtect, databaseUpdatedAt, accessibility, admins)
    }
    private fun isNonSystem(flags: Int) = flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
}
