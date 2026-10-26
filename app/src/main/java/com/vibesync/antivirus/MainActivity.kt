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
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.core.observer.SecurityAlertNotifier
import com.vibesync.antivirus.core.posture.PostureChangeNotifier
import com.vibesync.antivirus.presentation.SafeMobileScreen
import com.vibesync.antivirus.presentation.SafeMobileTheme

/** Offline-first entry point without ad, analytics, crash-reporting or Play update SDKs. */
class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocalePreferences.wrap(newBase))
    }
    private val themePreferences by lazy { ThemePreferences(this) }
    private var selectedTheme by mutableStateOf(AppTheme.MIDNIGHT)
    private var sharedText by mutableStateOf<String?>(null)
    private var openQuarantine by mutableStateOf(false)
    private var openDevicePosture by mutableStateOf(false)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(statusBarStyle = androidx.activity.SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = androidx.activity.SystemBarStyle.dark(android.graphics.Color.rgb(15, 23, 42)))
        lifecycleScope.launch { themePreferences.selected.collect { saved -> selectedTheme = saved } }
        sharedText = incomingSharedText(intent)
        openQuarantine = intent.getBooleanExtra(SecurityAlertNotifier.EXTRA_OPEN_QUARANTINE, false)
        openDevicePosture = intent.getBooleanExtra(PostureChangeNotifier.EXTRA_OPEN_POSTURE, false)
        setContent {
            SafeMobileTheme(theme = selectedTheme) {
                SafeMobileScreen(
                    repository = (application as SafeMobileApp).repository,
                    appTheme = selectedTheme,
                    onAppThemeChanged = { choice ->
                        selectedTheme = choice
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
        SecurityAlertNotifier.stopIncidentAudio()
    }
    private fun incomingSharedText(intent: Intent?): String? =
        if (intent?.action == Intent.ACTION_SEND) intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString() else null
}

