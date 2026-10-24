package com.vibesync.antivirus.core.observer

import android.content.Context
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import com.vibesync.antivirus.SafeMobileApp
import java.util.Locale

/**
 * One-shot, device-local TTS. It is gated by an explicit user preference (off by default).
 * The temporary engine shuts itself down after completion or error, so it does not outlive
 * the alert or retain an Activity/ViewModel.
 */
object SecurityVoiceAlert {
    fun speakIfEnabled(context: Context, message: String) {
        val enabled = context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .getBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, false)
        if (!enabled || message.isBlank()) return
        runCatching { OneShotSpeech(context.applicationContext, message).start() }
            .onFailure { android.util.Log.w(TAG, "Unable to initialize local TTS", it) }
    }

    private class OneShotSpeech(
        private val context: Context,
        private val message: String
    ) : TextToSpeech.OnInitListener {
        private var engine: TextToSpeech? = null
        private val utteranceId = "safemobile-security-${System.nanoTime()}"

        fun start() {
            engine = TextToSpeech(context, this)
        }

        override fun onInit(status: Int) {
            val tts = engine ?: return
            if (status != TextToSpeech.SUCCESS) {
                shutdown()
                return
            }
            runCatching { tts.language = Locale.getDefault() }
            tts.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(utteranceId: String?) = Unit
                override fun onDone(utteranceId: String?) = shutdown()
                @Deprecated("Deprecated in Android API; retained for callback compatibility.")
                override fun onError(utteranceId: String?) = shutdown()
                override fun onError(utteranceId: String?, errorCode: Int) = shutdown()
            })
            val result = tts.speak(message, TextToSpeech.QUEUE_FLUSH, null, utteranceId)
            if (result == TextToSpeech.ERROR) shutdown()
        }

        private fun shutdown() {
            val current = engine ?: return
            engine = null
            runCatching { current.stop() }
            runCatching { current.shutdown() }
        }
    }

    private const val TAG = "SafeMobileVoiceAlert"
}
