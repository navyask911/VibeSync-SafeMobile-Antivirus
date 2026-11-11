package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.res.Configuration
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.R
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

@RunWith(AndroidJUnit4::class)
class VoiceAlertLocaleTest {
    @Test fun hindiSpanishAndEnglishWarningsResolveFromLocalizedResources() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        for ((tag, start) in listOf("hi-IN" to "चेतावनी", "es-ES" to "Advertencia", "en-US" to "Warning")) {
            val localized = context.createConfigurationContext(Configuration(context.resources.configuration).apply {
                setLocale(Locale.forLanguageTag(tag))
            })
            assertTrue(localized.getString(R.string.voice_alert_malware_detected).startsWith(start))
        }
    }

    @Test fun kannadaWarningUsesKannadaTextAndDoesNotClaimInstalledAppWasQuarantined() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val localized = context.createConfigurationContext(Configuration(context.resources.configuration).apply {
            setLocale(Locale.forLanguageTag("kn-IN"))
        })
        val installed = localized.getString(R.string.voice_alert_malware_detected)
        assertTrue(installed.startsWith("ಎಚ್ಚರಿಕೆ"))
        assertTrue(installed.contains("ಅನ್‌ಇನ್‌ಸ್ಟಾಲ್"))
        assertNotEquals(installed, localized.getString(R.string.voice_malicious_quarantined))
    }
}
