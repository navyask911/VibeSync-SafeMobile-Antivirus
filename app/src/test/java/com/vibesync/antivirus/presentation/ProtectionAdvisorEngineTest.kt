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
                developerOptionsEnabled = false,
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
                developerOptionsEnabled = true,
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


    @Test
    fun developerOptionsDeductionAppliesOnlyWhenTheMasterSwitchIsEnabled() {
        val now = 1_800_000_000_000L
        fun evaluate(developerOptionsEnabled: Boolean?) = ProtectionAdvisorEngine.evaluate(
            inputs = ProtectionAdvisorInputs(
                totalScans = 1,
                threatsDetected = 0,
                folderSentinelConfigured = true,
                highRiskPostureCount = 0,
                notificationsEnabled = true,
                batteryUnrestricted = true,
                fullScreenIntentEnabled = true,
                databaseUpdatedAt = now,
                installSentinelEnabled = true,
                playProtectEnabled = true,
                usbDebuggingEnabled = false,
                developerOptionsEnabled = developerOptionsEnabled,
                voiceAlertsEnabled = true,
                meetsDeviceIntegrity = true,
                apiLevel = 36,
                nowMillis = now
            ),
            snoozedIds = emptySet()
        )

        val disabled = evaluate(false)
        assertEquals(100, disabled.score)
        assertEquals(0, disabled.pendingCount)
        assertEquals(AdvisorIssueGroup.COMPLETED,
            disabled.issues.single { it.id == "developer_options_enabled" }.group)

        val enabled = evaluate(true)
        assertEquals(97, enabled.score)
        assertEquals(1, enabled.pendingCount)
        assertEquals(3, enabled.issues.single { it.id == "developer_options_enabled" }.points)
        assertEquals(AdvisorIssueGroup.MINOR,
            enabled.issues.single { it.id == "developer_options_enabled" }.group)

        // A read failure/unavailable setting must not produce a Developer Options deduction.
        assertEquals(100, evaluate(null).score)
    }

}
