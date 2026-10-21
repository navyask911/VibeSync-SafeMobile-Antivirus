package com.vibesync.antivirus

import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.presentation.SafeMobileScreen
import com.vibesync.antivirus.presentation.SafeMobileTheme

/** Offline-first entry point without ad, analytics, crash-reporting or Play update SDKs. */
class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocalePreferences.wrap(newBase))
    }
    private var sharedText by mutableStateOf<String?>(null)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        sharedText = incomingSharedText(intent)
        setContent {
            SafeMobileTheme {
                SafeMobileScreen(
                    repository = (application as SafeMobileApp).repository,
                    sharedText = sharedText,
                    onSharedTextConsumed = { sharedText = null }
                )
            }
        }
    }
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        incomingSharedText(intent)?.let { sharedText = it }
    }
    private fun incomingSharedText(intent: Intent?): String? =
        if (intent?.action == Intent.ACTION_SEND) intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString() else null
}
