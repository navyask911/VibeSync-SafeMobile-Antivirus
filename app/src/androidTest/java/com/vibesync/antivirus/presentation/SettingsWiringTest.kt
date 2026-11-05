package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class SettingsWiringTest {
    @get:Rule
    val composeRule = createComposeRule()

    private val context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun renderSettings(content: @androidx.compose.runtime.Composable () -> Unit) {
        composeRule.setContent {
            CompositionLocalProvider(LocalDensity provides Density(density = 1f, fontScale = 2f)) {
                SafeMobileTheme(theme = AppTheme.LIGHT) {
                    Column(
                        modifier = Modifier.width(320.dp).verticalScroll(rememberScrollState())
                    ) {
                        content()
                    }
                }
            }
        }
    }

    @Test
    fun lightMidnightAndOledButtonsUpdateSelectedThemeState() {
        var selectedTheme by mutableStateOf(AppTheme.LIGHT)
        renderSettings {
            SafeMobileSettingsPanel(
                sentinelEnabled = false,
                onEnableSentinel = {},
                onDisableSentinel = {},
                appTheme = selectedTheme,
                onAppThemeChanged = { selectedTheme = it },
                installSentinelRunningOverride = false,
                installSentinelEnabledOverride = false,
                onInstallSentinelChanged = {}
            )
        }

        composeRule.onNodeWithTag("settings.theme.light").assertIsSelected()
        composeRule.onNodeWithTag("settings.theme.midnight").performScrollTo().performClick()
        composeRule.waitForIdle()
        assertEquals(AppTheme.MIDNIGHT, selectedTheme)
        composeRule.onNodeWithTag("settings.theme.midnight").assertIsSelected()

        composeRule.onNodeWithTag("settings.theme.oled").performScrollTo().performClick()
        composeRule.waitForIdle()
        assertEquals(AppTheme.OLED, selectedTheme)
        composeRule.onNodeWithTag("settings.theme.oled").assertIsSelected()

        composeRule.onNodeWithTag("settings.theme.light").performScrollTo().performClick()
        composeRule.waitForIdle()
        assertEquals(AppTheme.LIGHT, selectedTheme)
        composeRule.onNodeWithTag("settings.theme.light").assertIsSelected()
    }

    @Test
    fun securityAlertsSwitchUpdatesItsOwnerState() {
        var alertsEnabled by mutableStateOf(false)
        renderSettings {
            SafeMobileSettingsPanel(
                sentinelEnabled = false,
                onEnableSentinel = {},
                onDisableSentinel = {},
                securityAlertsEnabled = alertsEnabled,
                onSecurityAlertsChanged = { alertsEnabled = it },
                installSentinelRunningOverride = false,
                installSentinelEnabledOverride = false,
                onInstallSentinelChanged = {}
            )
        }

        composeRule.onNodeWithTag("settings.security-alerts").assertIsOff()
        composeRule.onNodeWithTag("settings.security-alerts").performScrollTo().performClick()
        composeRule.waitForIdle()
        assertEquals(true, alertsEnabled)
        composeRule.onNodeWithTag("settings.security-alerts").assertIsOn()
    }

    @Test
    fun installSentinelSwitchUpdatesItsOwnerStateWithoutStartingAService() {
        var sentinelEnabled by mutableStateOf(true)
        renderSettings {
            SafeMobileSettingsPanel(
                sentinelEnabled = false,
                onEnableSentinel = {},
                onDisableSentinel = {},
                installSentinelRunningOverride = true,
                installSentinelEnabledOverride = sentinelEnabled,
                onInstallSentinelChanged = { sentinelEnabled = it }
            )
        }

        composeRule.onNodeWithTag("settings.install-sentinel").assertIsOn()
        composeRule.onNodeWithTag("settings.install-sentinel").performScrollTo().performClick()
        composeRule.waitForIdle()
        assertEquals(false, sentinelEnabled)
        composeRule.onNodeWithTag("settings.install-sentinel").assertIsOff()
    }

    @Test
    fun settingsSubpageBackArrowReturnsToSettingsRoot() {
        var subRoute by mutableStateOf(SettingsSubRoute.SECURITY)
        renderSettings {
            SafeMobileSettingsPanel(
                sentinelEnabled = false,
                onEnableSentinel = {},
                onDisableSentinel = {},
                subRoute = subRoute,
                onSubRouteChanged = { subRoute = it },
                installSentinelRunningOverride = false,
                installSentinelEnabledOverride = false,
                onInstallSentinelChanged = {}
            )
        }

        composeRule.onNodeWithTag("settings.subpage.back").performClick()
        composeRule.waitForIdle()
        assertEquals(SettingsSubRoute.ROOT, subRoute)
    }

    @Test
    fun settingsGearAndBellIconsExposeAccessibleNodes() {
        renderSettings {
            SafeMobileSettingsPanel(
                sentinelEnabled = false,
                onEnableSentinel = {},
                onDisableSentinel = {},
                installSentinelRunningOverride = false,
                installSentinelEnabledOverride = false,
                onInstallSentinelChanged = {}
            )
        }

        composeRule.onNodeWithContentDescription(context.getString(R.string.language_settings))
            .assertExists()
        composeRule.onNodeWithContentDescription(context.getString(R.string.siren_test_settings_title))
            .assertExists()
    }
}
