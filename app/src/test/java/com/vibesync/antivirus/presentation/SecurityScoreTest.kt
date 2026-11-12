package com.vibesync.antivirus.presentation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SecurityScoreTest {
    private val now = 2_000_000_000L

    private fun healthyInputs(
        folderSentinelConfigured: Boolean = true,
        installSentinelEnabled: Boolean = true
    ) = ProtectionAdvisorInputs(
        totalScans = 1,
        threatsDetected = 0,
        folderSentinelConfigured = folderSentinelConfigured,
        highRiskPostureCount = 0,
        notificationsEnabled = true,
        batteryUnrestricted = true,
        fullScreenIntentEnabled = true,
        databaseUpdatedAt = now - 1_000L,
        installSentinelEnabled = installSentinelEnabled,
        playProtectEnabled = true,
        usbDebuggingEnabled = false,
        voiceAlertsEnabled = true,
        deviceAdminActive = true,
        apiLevel = 34,
        nowMillis = now
    )

    @Test
    fun noPendingActionsProducesPerfectScore() {
        val state = ProtectionAdvisorEngine.evaluate(healthyInputs(), emptySet())

        assertEquals(0, state.pendingCount)
        assertEquals(100, state.score)
    }

    @Test
    fun disablingFolderMonitoringDeductsExactlyTenPoints() {
        val state = ProtectionAdvisorEngine.evaluate(
            healthyInputs(folderSentinelConfigured = false),
            emptySet()
        )
        val issue = state.issues.single { it.id == "folder_sentinel" }

        assertEquals(10, issue.points)
        assertEquals(90, state.score)
        assertEquals(1, state.pendingCount)
    }

    @Test
    fun disablingInstallSentinelDeductsExactlyTwelvePoints() {
        val state = ProtectionAdvisorEngine.evaluate(
            healthyInputs(installSentinelEnabled = false),
            emptySet()
        )
        val issue = state.issues.single { it.id == "install_sentinel" }

        assertEquals(12, issue.points)
        assertEquals(88, state.score)
        assertEquals(1, state.pendingCount)
    }

    @Test
    fun independentMonitoringPenaltiesAccumulate() {
        val state = ProtectionAdvisorEngine.evaluate(
            healthyInputs(
                folderSentinelConfigured = false,
                installSentinelEnabled = false
            ),
            emptySet()
        )

        assertEquals(78, state.score)
        assertEquals(2, state.pendingCount)
    }

    @Test
    fun scoreIsClampedWhenAllProtectionActionsArePending() {
        val unsafe = ProtectionAdvisorInputs(
            totalScans = 0,
            threatsDetected = 3,
            folderSentinelConfigured = false,
            highRiskPostureCount = 3,
            notificationsEnabled = false,
            batteryUnrestricted = false,
            fullScreenIntentEnabled = false,
            databaseUpdatedAt = null,
            installSentinelEnabled = false,
            playProtectEnabled = false,
            usbDebuggingEnabled = true,
            voiceAlertsEnabled = false,
            apiLevel = 34,
            nowMillis = now
        )
        val state = ProtectionAdvisorEngine.evaluate(unsafe, emptySet())

        assertEquals(0, state.score)
        assertTrue(state.score in 0..100)
    }

    @Test
    fun snoozedUnresolvedActionKeepsItsDeduction() {
        val state = ProtectionAdvisorEngine.evaluate(
            healthyInputs(folderSentinelConfigured = false),
            setOf("folder_sentinel")
        )

        assertEquals(90, state.score)
        assertEquals(1, state.pendingCount)
    }
    @Test
    fun snoozedInstallSentinelKeepsItsTwelvePointDeduction() {
        val state = ProtectionAdvisorEngine.evaluate(
            healthyInputs(installSentinelEnabled = false),
            setOf("install_sentinel")
        )

        assertEquals(88, state.score)
        assertEquals(1, state.pendingCount)
        assertEquals(AdvisorIssueGroup.SNOOZED, state.issues.single { it.id == "install_sentinel" }.group)
    }
}

