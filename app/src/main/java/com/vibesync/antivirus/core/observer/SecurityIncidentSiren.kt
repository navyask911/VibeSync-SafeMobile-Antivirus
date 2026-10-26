package com.vibesync.antivirus.core.observer

import android.content.Context
import android.media.AudioAttributes
import android.media.AudioManager
import android.media.MediaPlayer
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.vibesync.antivirus.R

/** The notification channel is silent: this is the only owner of siren audio and its stop timer. */
internal object SecurityIncidentSiren {
    private val handler = Handler(Looper.getMainLooper())
    private var player: MediaPlayer? = null
    private var audioManager: AudioManager? = null
    private var previousVolume: Int? = null
    private var raisedVolume: Int? = null
    private val controller = IncidentSirenController(
        stopPlayback = ::releasePlayer,
        schedule = { task, delay -> handler.postDelayed(task, delay) },
        cancel = { handler.removeCallbacks(it) }
    )

    fun start(context: Context) {
        val app = context.applicationContext
        handler.post {
            try {
              controller.start {
                val attributes = AudioAttributes.Builder()
                    .setLegacyStreamType(AudioManager.STREAM_ALARM)
                    .setUsage(AudioAttributes.USAGE_ALARM)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build()
                val media = MediaPlayer.create(app, R.raw.security_alert_siren, attributes, 0)
                    ?: error("Siren resource could not be opened")
                player = media
                val audio = app.getSystemService(AudioManager::class.java)
                audioManager = audio
                if (audio != null) {
                    previousVolume = audio.getStreamVolume(AudioManager.STREAM_ALARM)
                    val maximum = audio.getStreamMaxVolume(AudioManager.STREAM_ALARM)
                    // DND, fixed-volume devices and OEM policy can reject volume changes.
                    runCatching {
                        audio.setStreamVolume(AudioManager.STREAM_ALARM, maximum, 0)
                        raisedVolume = maximum
                    }.onFailure { Log.w(TAG, "Alarm volume is controlled by Android", it) }
                }
                media.isLooping = true
                media.setVolume(1f, 1f)
                media.setOnErrorListener { _, _, _ -> controller.stop(); true }
                media.start()
              }
            } catch (error: Exception) {
                Log.w(TAG, "Unable to play local siren", error)
                controller.stop()
            }
        }
    }

    fun stop() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            // Also cancel a not-yet-started alarm posted by a background scan.
            handler.removeCallbacksAndMessages(null)
            controller.stop()
        } else handler.post { stop() }
    }

    private fun releasePlayer() {
        player?.let { current ->
            player = null
            runCatching { current.stop() }
            runCatching { current.release() }
        }
        val audio = audioManager
        val previous = previousVolume
        val raised = raisedVolume
        audioManager = null
        previousVolume = null
        raisedVolume = null
        if (audio != null && previous != null && raised != null) runCatching {
            // Preserve any volume adjustment the user made during the alarm.
            if (audio.getStreamVolume(AudioManager.STREAM_ALARM) == raised) {
                audio.setStreamVolume(AudioManager.STREAM_ALARM, previous, 0)
            }
        }.onFailure { Log.w(TAG, "Unable to restore alarm volume", it) }
    }

    private const val TAG = "SafeMobileSiren"
}
