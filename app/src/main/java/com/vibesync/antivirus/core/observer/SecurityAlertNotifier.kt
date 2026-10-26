package com.vibesync.antivirus.core.observer

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.presentation.SystemPackageGuard

/** Opt-in local alerts. Only exact malware matches receive the five-second incident siren. */
object SecurityAlertNotifier {
    const val CHANNEL_ID = "security_incident_v3"
    const val EXTRA_OPEN_QUARANTINE = "com.vibesync.antivirus.OPEN_QUARANTINE"
    internal const val EXTRA_EVENT_ID = "security.incident.event_id"

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID, context.getString(R.string.security_alert_channel_name), NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = context.getString(R.string.incident_channel_description)
            lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE
            // Channel audio cannot be stopped by our timer. MediaPlayer owns alarm audio.
            setSound(null, null)
            enableVibration(true)
        })
    }

    /** Only called after a durable, verified encrypted quarantine copy exists. */
    fun notifyQuarantinedFile(context: Context, fileName: String, eventId: String, confirmedMalicious: Boolean) {
        show(context, eventId, context.getString(R.string.security_alert_file_title),
            context.getString(R.string.security_alert_file_body, fileName.take(100)), null,
            if (confirmedMalicious) R.string.voice_malicious_quarantined else R.string.voice_suspicious_quarantined,
            confirmedMalicious)
    }

    fun notifyMaliciousApp(context: Context, packageName: String, eventId: String) {
        if (!runCatching { SystemPackageGuard.isUserInstalled(context, packageName) }.getOrDefault(false)) return
        show(context, eventId, context.getString(R.string.security_alert_malware_title),
            context.getString(R.string.security_alert_malware_body), packageName, R.string.voice_alert_malware_detected, true)
    }

    fun notifySuspiciousApp(context: Context, packageName: String, eventId: String) {
        show(context, eventId, context.getString(R.string.security_alert_review_title),
            context.getString(R.string.security_alert_review_body), null, R.string.voice_app_review, false)
    }

    private fun show(context: Context, eventId: String, title: String, body: String,
                     packageName: String?, voiceResource: Int, confirmed: Boolean) {
        val app = context.applicationContext
        SecurityVoiceAlert.speakIfEnabled(app, voiceResource)
        val enabled = app.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)
        if (!enabled) return
        if (confirmed) SecurityIncidentSiren.start(app)
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(app,
                Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "Notification permission denied; opt-in local audio remains available")
            return
        }
        ensureChannel(app)
        val open = if (confirmed && packageName != null) {
            Intent(app, ThreatDetectedActivity::class.java)
                .putExtra(ThreatDetectedActivity.EXTRA_PACKAGE, packageName)
        } else Intent(app, MainActivity::class.java).putExtra(EXTRA_OPEN_QUARANTINE, true)
        open.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(EXTRA_EVENT_ID, eventId)
            .setData(Uri.fromParts("safemobile-incident", eventId, null))
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val content = PendingIntent.getActivity(app, eventId.hashCode(), open, flags)
        val dismiss = PendingIntent.getBroadcast(app, eventId.hashCode(),
            Intent(app, SecurityAlertDismissReceiver::class.java).putExtra(EXTRA_EVENT_ID, eventId)
                .setData(Uri.fromParts("safemobile-dismiss", eventId, null)), flags)
        val builder = NotificationCompat.Builder(app, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher).setContentTitle(title).setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body)).setContentIntent(content)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(if (confirmed) NotificationCompat.CATEGORY_ALARM else NotificationCompat.CATEGORY_STATUS)
            .setAutoCancel(true).setOnlyAlertOnce(false).setDeleteIntent(dismiss)
            .addAction(R.drawable.ic_launcher, app.getString(if (packageName != null)
                R.string.incident_review_threat else R.string.security_alert_open_vault), content)
            .addAction(0, app.getString(R.string.incident_dismiss), dismiss)
        val manager = app.getSystemService(NotificationManager::class.java)
        if (confirmed && packageName != null &&
            (Build.VERSION.SDK_INT < 34 || manager?.canUseFullScreenIntent() == true)) {
            builder.setFullScreenIntent(content, true)
        } else if (confirmed && packageName != null) {
            Log.d(TAG, "Full-screen access unavailable; using heads-up incident notification")
        }
        runCatching { NotificationManagerCompat.from(app).notify(notificationId(eventId), builder.build()) }
            .onFailure { Log.w(TAG, "Unable to post local security alert", it) }
    }

    fun stopIncidentAudio() {
        SecurityIncidentSiren.stop()
        SecurityVoiceAlert.stop()
    }

    internal fun dismiss(context: Context, eventId: String?) {
        stopIncidentAudio()
        eventId?.let { NotificationManagerCompat.from(context).cancel(notificationId(it)) }
    }

    private fun notificationId(eventId: String): Int = 710_000 + (eventId.hashCode() and 0x000F_FFFF)
    private const val TAG = "SafeMobileSecurityAlert"
}

class SecurityAlertDismissReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        SecurityAlertNotifier.dismiss(context, intent.getStringExtra(SecurityAlertNotifier.EXTRA_EVENT_ID))
    }
}

