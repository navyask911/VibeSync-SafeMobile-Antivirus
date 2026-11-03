package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import app.cash.paparazzi.DeviceConfig
import app.cash.paparazzi.Paparazzi
import com.google.testing.junit.testparameterinjector.TestParameter
import com.google.testing.junit.testparameterinjector.TestParameterInjector
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.ui.theme.AppTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

enum class SnapshotPalette(val appTheme: AppTheme) {
    LIGHT(AppTheme.LIGHT),
    DARK(AppTheme.MIDNIGHT)
}

@RunWith(TestParameterInjector::class)
class DashboardSnapshotTest {
    @get:Rule
    val paparazzi = Paparazzi(deviceConfig = DeviceConfig.PIXEL_5)

    @Test
    fun securityDashboard(@TestParameter palette: SnapshotPalette) {
        paparazzi.snapshot {
            themed(palette) {
                SecurityDashboardV14(
                    advisor = ProtectionAdvisorState(
                        score = 91,
                        pendingCount = 1,
                        issues = listOf(
                            AdvisorIssueItem(
                                id = "notifications",
                                titleResource = R.string.security_alerts_title,
                                detailResource = R.string.incident_alerts_explanation,
                                points = 8,
                                group = AdvisorIssueGroup.MINOR,
                                destination = "settings"
                            )
                        )
                    ),
                    isPro = false,
                    adsReady = false,
                    scanRunning = false,
                    scanProgress = null,
                    downloadsActive = true,
                    chatFoldersActive = true,
                    installSentinelActive = true,
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
                    lastScanAt = 1_735_689_600_000L,
                    reviewCount = 1,
                    onOpenScanResults = {}
                )
            }
        }
    }

    @Test
    fun scanResultsScreen(@TestParameter palette: SnapshotPalette) {
        val results = listOf(
            ScanResult(
                packageOrPath = "samples/sample-threat.apk",
                displayName = "Sample APK",
                sha256 = null,
                md5 = null,
                verdict = ScanVerdict.THREAT,
                reasons = listOf("Local signature match"),
                durationMs = 34L
            ),
            ScanResult(
                packageOrPath = "samples/sample-review.apk",
                displayName = "Sample application",
                sha256 = null,
                md5 = null,
                verdict = ScanVerdict.SUSPICIOUS,
                reasons = listOf("Requires manual review"),
                durationMs = 28L
            ),
            ScanResult(
                packageOrPath = "samples/sample-clean.apk",
                displayName = "Sample document",
                sha256 = null,
                md5 = null,
                verdict = ScanVerdict.NO_MATCH,
                reasons = listOf("No local signature matched"),
                durationMs = 17L
            ),
            ScanResult(
                packageOrPath = "samples/sample-unreadable.apk",
                displayName = "Unreadable sample",
                sha256 = null,
                md5 = null,
                verdict = ScanVerdict.NOT_SCANNED,
                reasons = listOf("Content could not be read"),
                durationMs = 0L
            )
        )
        paparazzi.snapshot {
            themed(palette) {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                ) {
                    ScanResultsScreen(
                        results = results,
                        onUninstall = {},
                        onAppInfo = {},
                        onQuarantine = {},
                        onTrust = {},
                        onRemoveTrust = {}
                    )
                }
            }
        }
    }

    @Test
    fun settingsScreen(@TestParameter palette: SnapshotPalette) {
        paparazzi.snapshot {
            themed(palette) {
                Column(
                    modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                ) {
                    SafeMobileSettingsPanel(
                        sentinelEnabled = true,
                        onEnableSentinel = {},
                        onDisableSentinel = {},
                        strictMode = true,
                        securityAlertsEnabled = true,
                        onSecurityAlertsChanged = {},
                        onToggleProtection = {},
                        onStrictModeChanged = {},
                        appTheme = palette.appTheme,
                        onAppThemeChanged = {},
                        adPrivacyOptionsRequired = false,
                        isProForAds = true,
                        onShowAdPrivacyOptions = {},
                        onManageFolders = {},
                        onAddCustomFolder = {},
                        subRoute = SettingsSubRoute.ROOT,
                        onSubRouteChanged = {},
                        onOpenPro = {}
                    )
                }
            }
        }
    }

    @Composable
    private fun themed(palette: SnapshotPalette, content: @Composable () -> Unit) {
        SafeMobileTheme(theme = palette.appTheme) {
            Surface(
                modifier = Modifier.fillMaxSize(),
                color = MaterialTheme.colorScheme.background
            ) {
                content()
            }
        }
    }
}
