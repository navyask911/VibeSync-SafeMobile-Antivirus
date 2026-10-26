package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.res.Configuration
import android.media.AudioAttributes
import android.os.Handler
import android.os.Looper
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import android.util.Log
import androidx.annotation.StringRes
import com.vibesync.antivirus.SafeMobileApp
import java.util.Locale

/** Offline and opt-in. Translated text and the voice both use the device's default locale. */
object SecurityVoiceAlert {
    private val handler = Handler(Looper.getMainLooper())
    private var active: OneShotSpeech? = null

    fun speakIfEnabled(context: Context, @StringRes messageResource: Int) {
        val app = context.applicationContext
        if (!app.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
                .getBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, false)) return
        handler.post {
            active?.shutdown()
            runCatching {
                val locale = Locale.getDefault()
                val localized = app.createConfigurationContext(Configuration(app.resources.configuration).apply {
                    setLocale(locale)
                })
                OneShotSpeech(app, localized.getString(messageResource), locale).also {
                    active = it
                    it.start()
                }
            }.onFailure { Log.w(TAG, "Unable to initialize local TTS", it) }
        }
    }

    fun stop() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            handler.removeCallbacksAndMessages(null)
            active?.shutdown()
            active = null
        } else handler.post { stop() }
    }

    private class OneShotSpeech(private val context: Context, private val message: String,
                                private val locale: Locale) : TextToSpeech.OnInitListener {
        private var textToSpeech: TextToSpeech? = null
        private var closed = false
        private val timeout = Runnable { shutdown() }
        private val utteranceId = "safemobile-security-" + System.nanoTime()

        fun start() {
            textToSpeech = TextToSpeech(context, this)
            handler.postDelayed(timeout, 20_000L)
        }

        override fun onInit(status: Int) {
            // Defer: an engine may invoke onInit before its constructor has returned.
            handler.post {
                val tts = textToSpeech ?: return@post
                if (closed) return@post
                runCatching {
                    if (status != TextToSpeech.SUCCESS) { shutdown(); return@runCatching }
                    val availability = tts.setLanguage(locale)
                    if (availability == TextToSpeech.LANG_MISSING_DATA || availability == TextToSpeech.LANG_NOT_SUPPORTED) {
                        Log.w(TAG, "Local voice pack unavailable for " + locale.toLanguageTag())
                        shutdown()
                        return@runCatching
                    }
                    tts.setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_ALARM)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
                    tts.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                        override fun onStart(utteranceId: String?) = Unit
                        override fun onDone(utteranceId: String?) { handler.post { shutdown() } }
                        @Deprecated("Compatibility callback")
                        override fun onError(utteranceId: String?) { handler.post { shutdown() } }
                        override fun onError(utteranceId: String?, errorCode: Int) { handler.post { shutdown() } }
                    })
                    if (tts.speak(message, TextToSpeech.QUEUE_FLUSH, null, utteranceId) == TextToSpeech.ERROR) shutdown()
                }.onFailure { Log.w(TAG, "Unable to speak local warning", it); shutdown() }
            }
        }

        fun shutdown() {
            closed = true
            handler.removeCallbacks(timeout)
            val current = textToSpeech
            textToSpeech = null
            runCatching { current?.stop() }
            runCatching { current?.shutdown() }
            if (active === this) active = null
        }
    }

    private const val TAG = "SafeMobileVoiceAlert"
}

