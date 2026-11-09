package com.vibesync.antivirus.core.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test

class ProtectionGuardPreferencesTest {
    @Test
    fun guardStatePersistsAcrossReadsAndCountsOnlyEnabledControls() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val saved = ProtectionGuardPreferences.read(context)
        try {
            val next = ProtectionGuardPreferences.updateFromSystem(
                context, batteryExempt = true, deviceAdmin = false,
                highPriorityAlerts = true, safDirectoryWatch = false
            )
            assertEquals(2, next.activeCount)
            assertEquals(next, ProtectionGuardPreferences.read(context))
        } finally {
            ProtectionGuardPreferences.updateFromSystem(
                context, saved.batteryExempt, saved.deviceAdmin,
                saved.highPriorityAlerts, saved.safDirectoryWatch
            )
        }
    }
}
