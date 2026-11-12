package com.vibesync.antivirus.presentation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtectionAdvisorEngineTest {
    @Test
    fun pendingCountIncludesSnoozedUnresolvedIssues() {
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
                meetsDeviceIntegrity = true,
                apiLevel = 36,
                nowMillis = now
            ),
            snoozedIds = setOf("folder_sentinel", "notifications_on")
        )

        assertEquals(state.critical.size + state.minor.size + state.snoozed.size, state.pendingCount)
        assertTrue(state.snoozed.any { it.id == "folder_sentinel" })
        assertTrue(state.snoozed.any { it.id == "notifications_on" })
        assertEquals(4, state.pendingCount)
        assertEquals(2, state.snoozed.size)
        assertEquals(67, state.score)
    }
    @Test
    fun maximumUnresolvedDeductionsNormalizeToExactlyOneHundred() {
        val state = ProtectionAdvisorEngine.evaluate(
            inputs = ProtectionAdvisorInputs(
                totalScans = 0,
                threatsDetected = 0,
                folderSentinelConfigured = false,
                highRiskPostureCount = null,
                notificationsEnabled = false,
                batteryUnrestricted = false,
                fullScreenIntentEnabled = false,
                databaseUpdatedAt = null,
                installSentinelEnabled = false,
                playProtectEnabled = false,
                usbDebuggingEnabled = true,
                voiceAlertsEnabled = false,
                meetsDeviceIntegrity = false,
                apiLevel = 36
            ),
            snoozedIds = emptySet()
        )

        assertEquals(100, state.issues.sumOf { it.points })
        assertEquals(0, state.score)
        assertEquals(100, state.issues.filter {
            it.group != AdvisorIssueGroup.COMPLETED
        }.sumOf { it.points })
    }

}
