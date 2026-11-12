package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.width
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
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
            batteryActive = false,
            adminActive = false,
            safActive = false,
            onBatteryToggle = {},
            onAdminToggle = {},
            onSafToggle = {},
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
    fun fourPrimaryTabsExposeAccessibleVectorIcons() {
        render { V17BottomNavigationBar(selectedTab = "home", isDark = false, onSelect = {}) }
        composeRule.onNodeWithContentDescription("Shield tab").assertIsDisplayed()
        composeRule.onNodeWithContentDescription("Scan & Lab tab").assertIsDisplayed()
        composeRule.onNodeWithContentDescription("Tools Hub tab").assertIsDisplayed()
        composeRule.onNodeWithContentDescription("Console tab").assertIsDisplayed()
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
                batteryActive = false,
                adminActive = false,
                safActive = false,
                onBatteryToggle = {},
                onAdminToggle = {},
                onSafToggle = {},
                onImportYara = {},
                onThreatFeedSync = {},
                onBenchmarks = {},
                onOpenPro = {}
            )
        }

        composeRule.onNodeWithText("Dark Slate").performScrollTo().performClick()
        assertEquals(AppTheme.DARK_SLATE, selectedTheme)
        composeRule.onNodeWithText("Pure OLED Black").performScrollTo().performClick()
        assertEquals(AppTheme.OLED, selectedTheme)
        composeRule.onNodeWithText("Clean Light").performScrollTo().performClick()
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
                batteryActive = false,
                adminActive = false,
                safActive = false,
                onBatteryToggle = {},
                onAdminToggle = {},
                onSafToggle = {},
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
                batteryActive = false,
                adminActive = false,
                safActive = false,
                onBatteryToggle = {},
                onAdminToggle = {},
                onSafToggle = {},
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
                batteryActive = false,
                adminActive = false,
                safActive = false,
                onBatteryToggle = {},
                onAdminToggle = {},
                onSafToggle = {},
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
    @Test
    fun deviceAdminDisclosureRequiresExplicitConfirmation() {
        var confirmed = false
        render {
            DeviceAdminPermissionDisclosureDialog(
                onConfirm = { confirmed = true },
                onDismiss = {}
            )
        }

        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.security_guard_admin_consent_body))
            .assertIsDisplayed()
        assertEquals(false, confirmed)
        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.security_guard_consent_continue))
            .performClick()
        assertEquals(true, confirmed)
    }


    @Test
    fun forceLockActionRequiresExplicitConfirmation() {
        var lockRequests = 0
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
                batteryActive = false,
                adminActive = true,
                safActive = false,
                onBatteryToggle = {},
                onAdminToggle = {},
                onSafToggle = {},
                onLockDeviceNow = { lockRequests++ },
                onImportYara = {},
                onThreatFeedSync = {},
                onBenchmarks = {},
                onOpenPro = {}
            )
        }

        composeRule.onNodeWithTag("console.device-admin.lock")
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        assertEquals(0, lockRequests)

        composeRule.onNodeWithText(context.getString(com.vibesync.antivirus.R.string.device_admin_lock_confirm))
            .assertIsDisplayed()
            .performClick()
        assertEquals(1, lockRequests)
    }

}
