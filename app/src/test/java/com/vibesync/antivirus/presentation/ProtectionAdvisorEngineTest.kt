package com.vibesync.antivirus.presentation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionAdvisorEngineTest {
    @Test
    fun pendingCountMatchesOnlyActionableCriticalAndMinorIssues() {
        val now = 1_800_000_000_000L
        val state = ProtectionAdvisorEngine.evaluate(
            inputs = ProtectionAdvisorInputs(
                totalScans = 1,
                threatsDetected = 0,
                folderSentinelConfigured = false,
                highRiskPostureCount = 0,
                notificationsEnabled = false,
                batteryUnrestricted = false,
                fullScreenIntentEnabled = true,
                databaseUpdatedAt = now,
                installSentinelEnabled = false,
                playProtectEnabled = true,
                usbDebuggingEnabled = false,
                voiceAlertsEnabled = true,
                apiLevel = 36,
                nowMillis = now
            ),
            snoozedIds = setOf("folder_sentinel", "notifications_on")
        )

        assertEquals(state.critical.size + state.minor.size, state.pendingCount)
        assertTrue(state.snoozed.any { it.id == "folder_sentinel" })
        assertTrue(state.snoozed.any { it.id == "notifications_on" })
        assertEquals(2, state.pendingCount)
        assertEquals(79, state.score)
    }
}
