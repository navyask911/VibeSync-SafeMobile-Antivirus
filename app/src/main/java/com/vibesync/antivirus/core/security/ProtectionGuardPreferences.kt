package com.vibesync.antivirus.core.security

import android.content.Context
import com.vibesync.antivirus.SafeMobileApp

data class ProtectionGuardState(
    val batteryExempt: Boolean,
    val deviceAdmin: Boolean,
    val highPriorityAlerts: Boolean,
    val safDirectoryWatch: Boolean
) {
    val activeCount: Int
        get() = listOf(batteryExempt, deviceAdmin, highPriorityAlerts, safDirectoryWatch).count { it }
}

/** Mirrors verified Android permission/service state into shared security preferences. */
object ProtectionGuardPreferences {
    private const val BATTERY = "guard_battery_exempt"
    private const val ADMIN = "guard_device_admin"
    private const val FULL_SCREEN = "guard_high_priority_alerts"
    private const val SAF_WATCH = "guard_saf_directory_watch"

    private fun preferences(context: Context) =
        context.applicationContext.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)

    fun read(context: Context): ProtectionGuardState {
        val prefs = preferences(context)
        return ProtectionGuardState(
            prefs.getBoolean(BATTERY, false), prefs.getBoolean(ADMIN, false),
            prefs.getBoolean(FULL_SCREEN, false), prefs.getBoolean(SAF_WATCH, false)
        )
    }

    fun updateFromSystem(
        context: Context, batteryExempt: Boolean, deviceAdmin: Boolean,
        highPriorityAlerts: Boolean, safDirectoryWatch: Boolean
    ): ProtectionGuardState {
        val state = ProtectionGuardState(batteryExempt, deviceAdmin, highPriorityAlerts, safDirectoryWatch)
        preferences(context).edit()
            .putBoolean(BATTERY, state.batteryExempt)
            .putBoolean(ADMIN, state.deviceAdmin)
            .putBoolean(FULL_SCREEN, state.highPriorityAlerts)
            .putBoolean(SAF_WATCH, state.safDirectoryWatch)
            .apply()
        return state
    }
}
