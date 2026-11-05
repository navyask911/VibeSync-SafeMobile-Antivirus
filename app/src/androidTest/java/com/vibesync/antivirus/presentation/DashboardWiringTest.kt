package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertExists
import androidx.compose.ui.test.fetchSemanticsNodes
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodes
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class DashboardWiringTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun renderHome(
        onScan: () -> Unit = {},
        onOpenTools: () -> Unit = {},
        onInstallSentinel: () -> Unit = {},
        onFolders: () -> Unit = {},
        onLinkChecker: () -> Unit = {},
        onPosture: () -> Unit = {}
    ) {
        composeRule.setContent {
            SafeMobileTheme(theme = AppTheme.MIDNIGHT) {
                Box(Modifier.width(320.dp).height(900.dp)) {
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
                        onScan = onScan,
                        onCleaner = {},
                        onInstallSentinel = onInstallSentinel,
                        onFolders = onFolders,
                        onLinkChecker = onLinkChecker,
                        onPosture = onPosture,
                        onApps = {},
                        onQuarantine = {},
                        onOpenTools = onOpenTools,
                        lastScanAt = null,
                        reviewCount = 0,
                        onOpenScanResults = {},
                        installedAppsCount = 0,
                        inventoryLoaded = true,
                        quarantinedFilesCount = 0
                    )
                }
            }
        }
    }

    @Test
    fun scanNowButtonInvokesScanActionAndShieldIconIsAccessible() {
        var scanRequests = 0
        renderHome(onScan = { scanRequests++ })

        composeRule.onNodeWithText(context.getString(R.string.security_scan_now))
            .performScrollTo().performClick()
        assertEquals(1, scanRequests)
        composeRule.onNodeWithContentDescription(context.getString(R.string.security_scan_now))
            .assertExists()
    }

    @Test
    fun allToolsActionInvokesToolsNavigation() {
        var opened = false
        renderHome(onOpenTools = { opened = true })

        composeRule.onNodeWithText(context.getString(R.string.v140_analytics_tools))
            .performScrollTo().performClick()
        assertTrue(opened)
    }

    @Test
    fun everydayProtectionCardsOpenTheirMappedDestinations() {
        var destination = ""
        renderHome(
            onInstallSentinel = { destination = "sources" },
            onFolders = { destination = "sentinel" },
            onLinkChecker = { destination = "phishing" },
            onPosture = { destination = "posture" }
        )

        val routes = listOf(
            R.string.download_interceptor_label to "sources",
            R.string.sentinel_scope_title to "sentinel",
            R.string.nav_phishing to "phishing",
            R.string.posture_title to "posture"
        )
        routes.forEach { (labelResource, expectedDestination) ->
            composeRule.onNodeWithText(context.getString(labelResource))
                .performScrollTo().performClick()
            assertEquals(expectedDestination, destination)
        }
    }

    @Test
    fun toolsHubCardsOpenTheirMappedDestinations() {
        var destination = ""
        composeRule.setContent {
            SafeMobileTheme(theme = AppTheme.MIDNIGHT) {
                Column(Modifier.width(320.dp).verticalScroll(rememberScrollState())) {
                    ProtectionToolsHub(
                        onOpen = { destination = it },
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
        val routes = listOf(
            R.string.download_interceptor_label to "sources",
            R.string.sentinel_scope_title to "sentinel",
            R.string.nav_phishing to "phishing",
            R.string.posture_title to "posture",
            R.string.nav_apps to "apps",
            R.string.quarantine_vault_title to "quarantine",
            R.string.nav_history to "history",
            R.string.detection_capabilities_title to "capabilities"
        )
        routes.forEach { (labelResource, expectedDestination) ->
            composeRule.onNodeWithText(context.getString(labelResource))
                .performScrollTo().performClick()
            assertEquals(expectedDestination, destination)
        }
    }

    @Test
    fun dashboardTextStaysInside320DpAtTwoTimesFontScale() {
        composeRule.setContent {
            CompositionLocalProvider(LocalDensity provides Density(density = 1f, fontScale = 2f)) {
                SafeMobileTheme(theme = AppTheme.MIDNIGHT) {
                    Box(Modifier.width(320.dp).height(900.dp)) {
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
            }
        }
        assertTextNodesStayWithin320Dp()
    }

    private fun assertTextNodesStayWithin320Dp() {
        composeRule.waitForIdle()
        val matcher = SemanticsMatcher("text semantics") {
            it.config.contains(SemanticsProperties.Text)
        }
        val nodes = composeRule.onAllNodes(matcher, useUnmergedTree = true).fetchSemanticsNodes()
        assertTrue("Expected dashboard text semantics nodes", nodes.isNotEmpty())
        nodes.forEach { node ->
            val bounds = node.boundsInRoot
            assertTrue("Text starts outside viewport: $bounds", bounds.left >= 0f)
            assertTrue("Text extends beyond 320dp viewport: $bounds", bounds.right <= 320f)
        }
    }
}
