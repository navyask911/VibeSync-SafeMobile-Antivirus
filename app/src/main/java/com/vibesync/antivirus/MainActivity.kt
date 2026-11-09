package com.vibesync.antivirus

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import com.vibesync.antivirus.ui.theme.AppTheme
import com.vibesync.antivirus.ui.theme.ThemePreferences
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.activity.compose.setContent
import androidx.core.view.WindowCompat
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.core.observer.SecurityAlertNotifier
import com.vibesync.antivirus.core.posture.PostureChangeNotifier
import com.vibesync.antivirus.presentation.SafeMobileScreen
import com.vibesync.antivirus.presentation.SafeMobileTheme

/** Offline-first entry point; UMP consent is refreshed before any Free-tier AdMob request. */
class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocalePreferences.wrap(newBase))
    }
    private val themePreferences by lazy { ThemePreferences(this) }
    private var selectedTheme by mutableStateOf(AppTheme.DARK_SLATE)
    private var sharedText by mutableStateOf<String?>(null)
    private var openQuarantine by mutableStateOf(false)
    private var openDevicePosture by mutableStateOf(false)
    private var batteryStatusEpoch by mutableStateOf(0)
    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen()
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        applySystemBars(AppTheme.DARK_SLATE)
        lifecycleScope.launch { themePreferences.selected.collect { saved -> selectedTheme = saved; applySystemBars(saved) } }
        sharedText = incomingSharedText(intent)
        openQuarantine = intent.getBooleanExtra(SecurityAlertNotifier.EXTRA_OPEN_QUARANTINE, false)
        openDevicePosture = intent.getBooleanExtra(PostureChangeNotifier.EXTRA_OPEN_POSTURE, false)
        setContent {
            SafeMobileTheme(theme = selectedTheme) {
                SafeMobileScreen(
                    repository = (application as SafeMobileApp).repository,
                    batteryStatusEpoch = batteryStatusEpoch,
                    appTheme = selectedTheme,
                    onAppThemeChanged = { choice ->
                        selectedTheme = choice
                        applySystemBars(choice)
                        lifecycleScope.launch {
                            runCatching { themePreferences.save(choice) }
                                .onFailure { Log.e("SafeMobileTheme", "Could not save theme", it) }
                        }
                    },
                    sharedText = sharedText,
                    onSharedTextConsumed = { sharedText = null },
                    openQuarantine = openQuarantine,
                    onOpenQuarantineConsumed = { openQuarantine = false },
                    openDevicePosture = openDevicePosture,
                    onOpenDevicePostureConsumed = { openDevicePosture = false }
                )
            }
        }
        // Refresh UMP consent on every app launch. AdMobManager verifies Pro first,
        // shows any required privacy form, and initializes Mobile Ads only afterwards.
        lifecycleScope.launch {
            runCatching {
                (application as SafeMobileApp).adMobManager.refresh(this@MainActivity)
            }.onFailure {
                Log.w("SafeMobileConsent", "Consent unavailable; advertising remains disabled", it)
            }
        }
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        incomingSharedText(intent)?.let { sharedText = it }
        if (intent.getBooleanExtra(SecurityAlertNotifier.EXTRA_OPEN_QUARANTINE, false)) openQuarantine = true
        if (intent.getBooleanExtra(PostureChangeNotifier.EXTRA_OPEN_POSTURE, false)) openDevicePosture = true
    }
    override fun onResume() {
        super.onResume()
        batteryStatusEpoch++
        com.vibesync.antivirus.core.observer.InstallSentinelService.startFromVisibleUi(this)
        SecurityAlertNotifier.stopIncidentAudio()
    }
    private fun applySystemBars(theme: AppTheme) {
        val light = theme == AppTheme.LIGHT
        val background = when (theme) {
            AppTheme.DARK_SLATE -> android.graphics.Color.rgb(30, 41, 59)
            AppTheme.MIDNIGHT -> android.graphics.Color.rgb(15, 23, 42)
            AppTheme.OLED -> android.graphics.Color.BLACK
            AppTheme.LIGHT -> android.graphics.Color.rgb(244, 247, 250)
        }
        enableEdgeToEdge(
            statusBarStyle = if (light)
                androidx.activity.SystemBarStyle.light(android.graphics.Color.TRANSPARENT, background)
                else androidx.activity.SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = if (light)
                androidx.activity.SystemBarStyle.light(android.graphics.Color.TRANSPARENT, background)
                else androidx.activity.SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
    }

    private fun incomingSharedText(intent: Intent?): String? =
        if (intent?.action == Intent.ACTION_SEND) intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString() else null
}

