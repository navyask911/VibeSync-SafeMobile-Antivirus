package com.vibesync.antivirus.core.observer

import android.content.Context
import android.speech.tts.TextToSpeech
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.R
import java.util.Locale

/** Optional spoken alerts. Disabled by default; the user-selected system TTS engine determines processing. */
object SecurityVoiceAlert {
    const val PREF_VOICE_ALERTS_ENABLED = "voice_alerts_enabled"

    private var engine: TextToSpeech? = null
    private var ready = false
    private var pendingMessage: String? = null

    fun isEnabled(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .getBoolean(PREF_VOICE_ALERTS_ENABLED, false)

    @Synchronized
    fun announce(context: Context, confirmed: Boolean) {
        val app = context.applicationContext
        if (!isEnabled(app)) return
        pendingMessage = app.getString(
            if (confirmed) R.string.security_alert_confirmed_voice else R.string.security_alert_review_voice
        )
        if (engine != null) {
            if (ready) speakPendingLocked()
            return
        }
        engine = TextToSpeech(app) { result ->
            synchronized(this) {
                val active = engine ?: return@synchronized
                if (result != TextToSpeech.SUCCESS) {
                    active.shutdown()
                    engine = null
                    ready = false
                    pendingMessage = null
                    return@synchronized
                }
                val languageResult = active.setLanguage(Locale.getDefault())
                ready = languageResult != TextToSpeech.LANG_MISSING_DATA &&
                    languageResult != TextToSpeech.LANG_NOT_SUPPORTED
                if (ready) speakPendingLocked() else {
                    active.shutdown()
                    engine = null
                    pendingMessage = null
                }
            }
        }
    }

    private fun speakPendingLocked() {
        val message = pendingMessage ?: return
        pendingMessage = null
        runCatching { engine?.speak(message, TextToSpeech.QUEUE_FLUSH, null, "safemobile-security-alert") }
    }

    @Synchronized
    fun shutdown() {
        ready = false
        pendingMessage = null
        engine?.stop()
        engine?.shutdown()
        engine = null
    }
}
