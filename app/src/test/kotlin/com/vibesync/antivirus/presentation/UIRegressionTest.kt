package com.vibesync.antivirus.presentation

import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Rule
import org.junit.Test

/**
 * Snapshot stress cases for the main Compose surfaces.
 *
 * Home, Protection Tools and Settings render on a full-screen Pixel 6
 * profile at normal, 1.5x and 2.0x font scale. The connected Compose bounds
 * test separately retains its 320dp narrow-viewport coverage.
 */
abstract class UIRegressionTestBase(private val testFontScale: Float) {
    @get:Rule
    val paparazzi = Paparazzi(
        deviceConfig = DeviceConfig.PIXEL_6.copy(
            screenHeight = 2200,
            fontScale = testFontScale
        )
    )

    @Test
    fun homeScreenAtFontScale() {
        paparazzi.snapshot {
            themed {
                SecurityDashboardV14(
                    advisor = ProtectionAdvisorState(score = 100, pendingCount = 0, issues = emptyList()),
                    isPro = false,
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

    @Test
    fun toolsScreenAtFontScale() {
        paparazzi.snapshot {
            themed {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                ) {
                    ProtectionToolsHub(
                        onOpen = {},
                        onScanInstalled = {},
                        onPickApk = {},
                        onScanFolder = {},
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
    }

    @Test
    fun settingsScreenAtFontScale() {
        paparazzi.snapshot {
            themed {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                ) {
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

    @Composable
    private fun themed(content: @Composable () -> Unit) {
        val baseContext = LocalContext.current
        val snapshotContext = remember(baseContext) { SnapshotContextWrapper(baseContext) }
        val lifecycleOwner = remember {
            object : LifecycleOwner {
                override val lifecycle: Lifecycle = LifecycleRegistry(this).apply {
                    currentState = Lifecycle.State.RESUMED
                }
            }
        }
        val activityResultRegistryOwner = remember { SnapshotActivityResultRegistryOwner() }
        CompositionLocalProvider(
            LocalContext provides snapshotContext,
            LocalLifecycleOwner provides lifecycleOwner,
            LocalActivityResultRegistryOwner provides activityResultRegistryOwner
        ) {
            SafeMobileTheme(theme = AppTheme.MIDNIGHT) {
                Surface(modifier = Modifier.fillMaxSize()) { content() }
            }
        }
    }
}

class UIRegressionFontScale100Test : UIRegressionTestBase(1.0f)
class UIRegressionFontScale150Test : UIRegressionTestBase(1.5f)
class UIRegressionFontScale200Test : UIRegressionTestBase(2.0f)
