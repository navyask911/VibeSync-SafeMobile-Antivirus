package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.LifecycleRegistry
import androidx.lifecycle.compose.LocalLifecycleOwner
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
        val lifecycleOwner = remember {
            object : LifecycleOwner {
                override val lifecycle: Lifecycle = LifecycleRegistry(this).apply {
                    currentState = Lifecycle.State.RESUMED
                }
            }
        }
        val baseContext = LocalContext.current
        val snapshotContext = remember(baseContext) { SnapshotContextWrapper(baseContext) }
        CompositionLocalProvider(
            LocalLifecycleOwner provides lifecycleOwner,
            LocalContext provides snapshotContext
        ) {
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
}


// Paparazzi's host-side Android Context does not provide working SharedPreferences editors.
// The Settings screen only reads local preferences during rendering; this in-memory context
// reproduces that contract without touching device storage or production persistence code.
private class SnapshotContextWrapper(base: Context) : ContextWrapper(base) {
    private val preferences = mutableMapOf<String, SharedPreferences>()

    override fun getApplicationContext(): Context = this

    override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
        preferences.getOrPut(name) { SnapshotSharedPreferences() }
}

private class SnapshotSharedPreferences : SharedPreferences {
    private val values = linkedMapOf<String, Any?>()
    private val listeners = linkedSetOf<SharedPreferences.OnSharedPreferenceChangeListener>()

    @Synchronized
    override fun getAll(): MutableMap<String, *> = values.toMutableMap()

    @Synchronized
    override fun getString(key: String, defValue: String?): String? =
        (values[key] as? String) ?: defValue

    @Synchronized
    override fun getStringSet(key: String, defValues: MutableSet<String>?): MutableSet<String>? =
        ((values[key] as? Set<*>)?.filterIsInstance<String>()?.toMutableSet())
            ?: defValues?.toMutableSet()

    @Synchronized
    override fun getInt(key: String, defValue: Int): Int = values[key] as? Int ?: defValue

    @Synchronized
    override fun getLong(key: String, defValue: Long): Long = values[key] as? Long ?: defValue

    @Synchronized
    override fun getFloat(key: String, defValue: Float): Float = values[key] as? Float ?: defValue

    @Synchronized
    override fun getBoolean(key: String, defValue: Boolean): Boolean =
        values[key] as? Boolean ?: defValue

    @Synchronized
    override fun contains(key: String): Boolean = values.containsKey(key)

    override fun edit(): SharedPreferences.Editor = SnapshotEditor()

    @Synchronized
    override fun registerOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener
    ) {
        listeners += listener
    }

    @Synchronized
    override fun unregisterOnSharedPreferenceChangeListener(
        listener: SharedPreferences.OnSharedPreferenceChangeListener
    ) {
        listeners -= listener
    }

    private inner class SnapshotEditor : SharedPreferences.Editor {
        private val updates = linkedMapOf<String, Any?>()
        private val removals = linkedSetOf<String>()
        private var clearRequested = false

        override fun putString(key: String, value: String?): SharedPreferences.Editor =
            update(key, value)

        override fun putStringSet(
            key: String,
            values: MutableSet<String>?
        ): SharedPreferences.Editor = update(key, values?.toSet())

        override fun putInt(key: String, value: Int): SharedPreferences.Editor = update(key, value)
        override fun putLong(key: String, value: Long): SharedPreferences.Editor = update(key, value)
        override fun putFloat(key: String, value: Float): SharedPreferences.Editor = update(key, value)
        override fun putBoolean(key: String, value: Boolean): SharedPreferences.Editor = update(key, value)

        private fun update(key: String, value: Any?): SharedPreferences.Editor {
            updates[key] = value
            removals -= key
            return this
        }

        override fun remove(key: String): SharedPreferences.Editor {
            updates -= key
            removals += key
            return this
        }

        override fun clear(): SharedPreferences.Editor {
            clearRequested = true
            updates.clear()
            removals.clear()
            return this
        }

        override fun commit(): Boolean {
            val changed = linkedSetOf<String>()
            synchronized(this@SnapshotSharedPreferences) {
                if (clearRequested) {
                    changed += values.keys
                    values.clear()
                }
                removals.forEach { key ->
                    if (values.remove(key) != null) changed += key
                }
                updates.forEach { (key, value) ->
                    if (values[key] != value) {
                        values[key] = value
                        changed += key
                    }
                }
                changed.forEach { key ->
                    listeners.toList().forEach { it.onSharedPreferenceChanged(this@SnapshotSharedPreferences, key) }
                }
            }
            return true
        }

        override fun apply() {
            commit()
        }
    }
}
