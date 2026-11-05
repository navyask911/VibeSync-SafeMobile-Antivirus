package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.fetchSemanticsNodes
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodes
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class UIRegressionBoundsTest {
    @get:Rule
    val composeRule = createComposeRule()

    private fun renderAndAssertTextFits(content: @androidx.compose.runtime.Composable () -> Unit) {
        composeRule.setContent {
            CompositionLocalProvider(LocalDensity provides Density(density = 1f, fontScale = 2f)) {
                SafeMobileTheme(theme = AppTheme.MIDNIGHT) {
                    Box(Modifier.width(320.dp).height(900.dp)) { content() }
                }
            }
        }
        composeRule.waitForIdle()
        val matcher = SemanticsMatcher("text semantics") {
            it.config.contains(SemanticsProperties.Text)
        }
        val nodes = composeRule.onAllNodes(matcher, useUnmergedTree = true).fetchSemanticsNodes()
        assertTrue("Expected text nodes for the rendered surface", nodes.isNotEmpty())
        nodes.forEach { node ->
            val bounds = node.boundsInRoot
            assertTrue("Text begins outside the 320dp viewport: $bounds", bounds.left >= 0f)
            assertTrue("Text overflows the 320dp viewport: $bounds", bounds.right <= 320f)
        }
    }

    @Test
    fun homeTextStaysInsideSmallViewport() {
        renderAndAssertTextFits {
            SecurityDashboardV14(
                advisor = ProtectionAdvisorState(score = 100, pendingCount = 0, issues = emptyList()),
                isPro = true,
                adsReady = false,
                scanRunning = false,
                scanProgress = null,
                downloadsActive = false,
                chatFoldersActive = false,
                installSentinelActive = false,
                onOpenAdvisor = {},
                onOpenPro = {},
                onScan = {},
                onCleaner = {},
                onInstallSentinel = {},
                onFolders = {},
                onLinkChecker = {},
                onPosture = {},
                onApps = {},
                onQuarantine = {},
                onOpenTools = {},
                lastScanAt = null,
                reviewCount = 0,
                onOpenScanResults = {},
                installedAppsCount = 0,
                inventoryLoaded = true,
                quarantinedFilesCount = 0
            )
        }
    }

    @Test
    fun toolsTextStaysInsideSmallViewport() {
        renderAndAssertTextFits {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                ProtectionToolsHub(
                    onOpen = {},
                    onScanInstalled = {},
                    onPickApk = {},
                    installSentinelActive = false,
                    foldersActive = false,
                    pendingActions = 0,
                    installedAppsCount = 0,
                    inventoryLoaded = true,
                    quarantinedFilesCount = 0
                )
            }
        }
    }

    @Test
    fun settingsTextStaysInsideSmallViewport() {
        renderAndAssertTextFits {
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                SafeMobileSettingsPanel(
                    sentinelEnabled = false,
                    onEnableSentinel = {},
                    onDisableSentinel = {},
                    securityAlertsEnabled = false,
                    onSecurityAlertsChanged = {},
                    appTheme = AppTheme.MIDNIGHT,
                    onAppThemeChanged = {},
                    installSentinelRunningOverride = false,
                    installSentinelEnabledOverride = false,
                    onInstallSentinelChanged = {}
                )
            }
        }
    }
}
