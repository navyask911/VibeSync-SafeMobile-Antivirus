package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.height
import androidx.test.platform.app.InstrumentationRegistry
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class SettingsWiringTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun render(content: @androidx.compose.runtime.Composable () -> Unit = {
        V17ConsoleSettingsScreen(
            isDark = false,
            appTheme = AppTheme.LIGHT,
            onAppThemeChanged = {},
            sirenEnabled = false,
            onSirenChanged = {},
            voiceEnabled = false,
            onVoiceChanged = {},
            installSentinelEnabled = false,
            installSentinelRunning = false,
            onInstallSentinelChanged = {},
            globalIntelEnabled = false,
            onGlobalIntelChanged = {},
            onImportYara = {},
            onThreatFeedSync = {},
            onBenchmarks = {},
            onOpenPro = {}
        )
    }) {
        composeRule.setContent {
            SafeMobileTheme(theme = AppTheme.LIGHT) {
                Column(Modifier.width(360.dp).height(900.dp)) {
                    content()
                }
            }
        }
    }

    @Test
    fun appearanceThemeChoicesUpdateTheOwningPreferenceState() {
        var selectedTheme by mutableStateOf(AppTheme.LIGHT)
        render {
            V17ConsoleSettingsScreen(
                isDark = false,
                appTheme = selectedTheme,
                onAppThemeChanged = { selectedTheme = it },
                sirenEnabled = false,
                onSirenChanged = {},
                voiceEnabled = false,
                onVoiceChanged = {},
                installSentinelEnabled = false,
                installSentinelRunning = false,
                onInstallSentinelChanged = {},
                globalIntelEnabled = false,
                onGlobalIntelChanged = {},
                onImportYara = {},
                onThreatFeedSync = {},
                onBenchmarks = {},
                onOpenPro = {}
            )
        }

        composeRule.onNodeWithText("Dark").performScrollTo().performClick()
        assertEquals(AppTheme.MIDNIGHT, selectedTheme)
        composeRule.onNodeWithText("OLED").performScrollTo().performClick()
        assertEquals(AppTheme.OLED, selectedTheme)
        composeRule.onNodeWithText("Light").performScrollTo().performClick()
        assertEquals(AppTheme.LIGHT, selectedTheme)
    }

    @Test
    fun sirenVoiceAndInstallSentinelSwitchesUpdateTheirOwnerState() {
        var siren by mutableStateOf(false)
        var voice by mutableStateOf(false)
        var sentinel by mutableStateOf(false)
        render {
            V17ConsoleSettingsScreen(
                isDark = false,
                appTheme = AppTheme.LIGHT,
                onAppThemeChanged = {},
                sirenEnabled = siren,
                onSirenChanged = { siren = it },
                voiceEnabled = voice,
                onVoiceChanged = { voice = it },
                installSentinelEnabled = sentinel,
                installSentinelRunning = false,
                onInstallSentinelChanged = { sentinel = it },
                globalIntelEnabled = false,
                onGlobalIntelChanged = {},
                onImportYara = {},
                onThreatFeedSync = {},
                onBenchmarks = {},
                onOpenPro = {}
            )
        }

        composeRule.onNodeWithTag("console.siren").assertIsOff().performScrollTo().performClick()
        composeRule.onNodeWithTag("console.voice").assertIsOff().performScrollTo().performClick()
        composeRule.onNodeWithTag("console.install-sentinel").assertIsOff().performScrollTo().performClick()
        composeRule.waitForIdle()
        assertEquals(true, siren)
        assertEquals(true, voice)
        assertEquals(true, sentinel)
        composeRule.onNodeWithTag("console.siren").assertIsOn()
        composeRule.onNodeWithTag("console.voice").assertIsOn()
        composeRule.onNodeWithTag("console.install-sentinel").assertIsOn()
    }

    @Test
    fun globalIntelOptInIsConnectedToItsOwningState() {
        var optedIn by mutableStateOf(false)
        render {
            V17ConsoleSettingsScreen(
                isDark = false,
                appTheme = AppTheme.LIGHT,
                onAppThemeChanged = {},
                sirenEnabled = false,
                onSirenChanged = {},
                voiceEnabled = false,
                onVoiceChanged = {},
                installSentinelEnabled = false,
                installSentinelRunning = false,
                onInstallSentinelChanged = {},
                globalIntelEnabled = optedIn,
                onGlobalIntelChanged = { optedIn = it },
                onImportYara = {},
                onThreatFeedSync = {},
                onBenchmarks = {},
                onOpenPro = {}
            )
        }

        composeRule.onNodeWithText("Advanced Telemetry & Rules").performScrollTo().performClick()
        composeRule.onNodeWithTag("console.global-intel").performScrollTo().performClick()
        assertEquals(true, optedIn)
    }

    @Test
    fun advancedTelemetryRowsRemainReadableWhenExpanded() {
        render()
        composeRule.onNodeWithText("Advanced Telemetry & Rules").performScrollTo().performClick()

        composeRule.onNodeWithText("YARA custom rules").performScrollTo().assertExists()
        composeRule.onNodeWithText("Import a local .yar rule.").performScrollTo().assertExists()
        composeRule.onNodeWithText("ThreatFeed Sync").performScrollTo().assertExists()
        composeRule.onNodeWithText("Run the configured feed sync.").performScrollTo().assertExists()
        composeRule.onNodeWithText("Benchmarks & Analytics").performScrollTo().assertExists()
        composeRule.onNodeWithText("Review local scan timing and results.").performScrollTo().assertExists()
    }

    @Test
    fun advancedActionsInvokeYaraThreatFeedAndBenchmarkCallbacks() {
        var yaraImports = 0
        var threatSyncs = 0
        var benchmarks = 0
        render {
            V17ConsoleSettingsScreen(
                isDark = false,
                appTheme = AppTheme.LIGHT,
                onAppThemeChanged = {},
                sirenEnabled = false,
                onSirenChanged = {},
                voiceEnabled = false,
                onVoiceChanged = {},
                installSentinelEnabled = false,
                installSentinelRunning = false,
                onInstallSentinelChanged = {},
                globalIntelEnabled = false,
                onGlobalIntelChanged = {},
                onImportYara = { yaraImports++ },
                onThreatFeedSync = { threatSyncs++ },
                onBenchmarks = { benchmarks++ },
                onOpenPro = {}
            )
        }

        composeRule.onNodeWithText("Advanced Telemetry & Rules").performScrollTo().performClick()
        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.detection_capabilities_import_yara)).performScrollTo().performClick()
        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.threat_feed_sync_now)).performScrollTo().performClick()
        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.open_feature)).performScrollTo().performClick()
        assertEquals(1, yaraImports)
        assertEquals(1, threatSyncs)
        assertEquals(1, benchmarks)
    }
}
