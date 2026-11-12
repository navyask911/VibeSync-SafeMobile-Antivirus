package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.compose.LocalLifecycleOwner
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(TestParameterInjector::class)
class V17TabsSnapshotTest {
    @get:Rule
    val paparazzi = Paparazzi(deviceConfig = DeviceConfig.PIXEL_6.copy(screenHeight = 2200))

    @Test
    fun shieldHomeTab(@TestParameter palette: SnapshotPalette) {
        paparazzi.snapshot {
            themed(palette, "home") {
                V17ShieldScreen(
                    isDark = palette.appTheme != AppTheme.LIGHT,
                    securityScore = 85,
                    isPro = false,
                    activeGuards = 3,
                    liveSentinelActive = true,
                    posturePassed = 7,
                    quarantinedFilesCount = 2,
                    onOpenSetup = {},
                    onOpenLiveSentinel = {},
                    onOpenPosture = {},
                    onOpenDetection = {},
                    onOpenThreatDb = {}
                )
            }
        }
    }

    @Test
    fun scanAndLabTab(@TestParameter palette: SnapshotPalette) {
        val result = ScanResult(
            packageOrPath = "com.example.safe.sample",
            displayName = "Sample application",
            sha256 = null,
            md5 = null,
            verdict = ScanVerdict.NO_MATCH,
            reasons = listOf("No local signature matched"),
            durationMs = 18L,
            packageName = "com.example.safe.sample"
        )
        paparazzi.snapshot {
            themed(palette, "scan") {
                V17ScanLabScreen(
                    isDark = palette.appTheme != AppTheme.LIGHT,
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
        }
    }

    @Test
    fun toolsHubTab(@TestParameter palette: SnapshotPalette) {
        paparazzi.snapshot {
            themed(palette, "tools") {
                V17ToolsHubScreen(
                    isDark = palette.appTheme != AppTheme.LIGHT,
                    onOpen = {}
                )
            }
        }
    }

    @Test
    fun consoleSettingsTab(@TestParameter palette: SnapshotPalette) {
        paparazzi.snapshot {
            themed(palette, "settings") {
                V17ConsoleSettingsScreen(
                    isDark = palette.appTheme != AppTheme.LIGHT,
                    appTheme = palette.appTheme,
                    onAppThemeChanged = {},
                    sirenEnabled = true,
                    onSirenChanged = {},
                    voiceEnabled = false,
                    onVoiceChanged = {},
                    installSentinelEnabled = true,
                    installSentinelRunning = true,
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
        }
    }

    @Composable
    private fun themed(palette: SnapshotPalette, selectedTab: String, content: @Composable () -> Unit) {
        val baseContext = LocalContext.current
        val snapshotContext = remember(baseContext) { SnapshotContextWrapper(baseContext) }
        val lifecycleOwner = remember {
            object : LifecycleOwner {
                override val lifecycle: Lifecycle = LifecycleRegistry(this).apply {
                    currentState = Lifecycle.State.RESUMED
                }
            }
        }
        CompositionLocalProvider(
            LocalLifecycleOwner provides lifecycleOwner,
            LocalContext provides snapshotContext
        ) {
            SafeMobileTheme(theme = palette.appTheme) {
                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    topBar = {
                        V17TopBar(
                            appTheme = palette.appTheme,
                            isPro = false,
                            showBack = false,
                            onThemeToggle = {},
                            onProClick = {},
                            onBack = {}
                        )
                    },
                    bottomBar = {
                        V17BottomNavigationBar(
                            selectedTab = selectedTab,
                            isDark = palette.appTheme != AppTheme.LIGHT,
                            onSelect = {}
                        )
                    },
                    containerColor = MaterialTheme.colorScheme.background
                ) { insets ->
                    Surface(
                        modifier = Modifier.fillMaxSize().padding(insets),
                        color = MaterialTheme.colorScheme.background
                    ) { content() }
                }
            }
        }
    }
}
