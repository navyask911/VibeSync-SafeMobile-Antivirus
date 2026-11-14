package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.security.SecurityVerificationState
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class DashboardWiringTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context
        get() = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext

    private fun render(content: @Composable () -> Unit) {
        composeRule.setContent {
            SafeMobileTheme(theme = AppTheme.MIDNIGHT) {
                Box(Modifier.fillMaxSize()) { content() }
            }
        }
    }

    @Test
    fun shieldSetupBannerOpensUnifiedPermissionChecklist() {
        var opened = false
        render {
            V17ShieldScreen(
                isDark = true,
                securityScore = 72,
                isPro = false,
                activeGuards = 2,
                totalGuardChecks = 3,
                isScanning = false,
                onStartScan = {},
                folderMonitorActive = false,
                monitoredFolderCount = 0,
                hashDatabaseActive = true,
                signedThreatIndicatorCount = 0,
                yaraEngineActive = true,
                integrityState = SecurityVerificationState(),
                advisorState = ProtectionAdvisorState(score = 100, pendingCount = 0, issues = emptyList()),
                onOpenAdvisorIssue = {},
                onSnoozeAdvisorIssue = {},
                onRestoreAdvisorIssue = {},
                liveSentinelActive = false,
                posturePassed = null,
                quarantinedFilesCount = 0,
                onOpenSetup = { opened = true },
                onOpenLiveSentinel = {},
                onOpenPosture = {},
                onOpenDetection = {},
                onOpenThreatDb = {}
            )
        }

        composeRule.onNodeWithText("Protection Setup: 2/3 Active")
            .performScrollTo().performClick()
        assertTrue(opened)
    }

    @Test
    fun shieldBentoTilesOpenTheirMappedDestinations() {
        var destination = ""
        render {
            V17ShieldScreen(
                isDark = true,
                securityScore = 85,
                isPro = true,
                activeGuards = 3,
                totalGuardChecks = 6,
                isScanning = false,
                onStartScan = {},
                folderMonitorActive = true,
                monitoredFolderCount = 2,
                hashDatabaseActive = true,
                signedThreatIndicatorCount = 2,
                yaraEngineActive = true,
                integrityState = SecurityVerificationState(),
                advisorState = ProtectionAdvisorState(score = 100, pendingCount = 0, issues = emptyList()),
                onOpenAdvisorIssue = {},
                onSnoozeAdvisorIssue = {},
                onRestoreAdvisorIssue = {},
                liveSentinelActive = true,
                posturePassed = 7,
                quarantinedFilesCount = 1,
                onOpenSetup = {},
                onOpenLiveSentinel = { destination = "sentinel" },
                onOpenPosture = { destination = "posture" },
                onOpenDetection = { destination = "capabilities" },
                onOpenThreatDb = { destination = "quarantine" }
            )
        }

        listOf(
            "Live Sentinel Status" to "sentinel",
            "Device Posture" to "posture",
            "AI Engine Status" to "capabilities",
            "Threat DB & Vault" to "quarantine"
        ).forEach { (label, expected) ->
            composeRule.onNodeWithText(label).performScrollTo().performClick()
            assertEquals(expected, destination)
        }
    }

    @Test
    fun scanLabQuickAndDeepModesInvokeTheCorrectExistingScanActions() {
        var quickScans = 0
        var deepScans = 0
        render {
            V17ScanLabScreen(
                isDark = true,
                state = SafeMobileUiState(),
                onStartQuickScan = { quickScans++ },
                onStartDeepScan = { deepScans++ },
                onCancelScan = {},
                onUninstall = {},
                onAppInfo = {},
                onQuarantine = {},
                onTrust = {},
                onRemoveTrust = {}
            )
        }

        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.scan_installed)).performScrollTo().performClick()
        composeRule.onNodeWithText("Deep Storage (Worker)").performScrollTo().performClick()
        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.cleaner_scan_storage)).performScrollTo().performClick()

        assertEquals(1, quickScans)
        assertEquals(1, deepScans)
    }

    @Test
    fun scanResultExpandsTheFourLayerEnsembleBreakdown() {
        val result = ScanResult(
            packageOrPath = "com.example.ensemble",
            displayName = "Ensemble sample",
            sha256 = null,
            md5 = null,
            verdict = ScanVerdict.SUSPICIOUS,
            reasons = listOf("Review required"),
            durationMs = 14L,
            packageName = "com.example.ensemble"
        )
        render {
            V17ScanLabScreen(
                isDark = true,
                state = SafeMobileUiState(results = listOf(result)),
                onStartQuickScan = {},
                onStartDeepScan = {},
                onCancelScan = {},
                onUninstall = {},
                onAppInfo = {},
                onQuarantine = {},
                onTrust = {},
                onRemoveTrust = {}
            )
        }

        composeRule.onNodeWithText("Ensemble sample").performScrollTo().performClick()
        composeRule.onNodeWithText("ThreatEnsembleEvaluator", substring = true).assertExists()
        composeRule.onNodeWithText("1. SHA-256 Hash").assertExists()
        composeRule.onNodeWithText("2. YARA Rules").assertExists()
        composeRule.onNodeWithText("3. ML Behavioral Model").assertExists()
        composeRule.onNodeWithText("4. Static / DEX Heuristics · No findings").assertExists()
    }

    @Test
    fun toolsHubCardsNavigateToAllFiveTools() {
        var destination = ""
        render {
            V17ToolsHubScreen(isDark = true, onOpen = { destination = it })
        }

        listOf(
            "Device Posture" to "posture",
            "Link Checker" to "phishing",
            "Quarantine Vault" to "quarantine",
            "Folder Monitor" to "sentinel",
            "System App Guard" to "guardian",
        ).forEach { (label, expected) ->
            composeRule.onNodeWithText(label).performScrollTo().performClick()
            assertEquals(expected, destination)
        }
    }
}
