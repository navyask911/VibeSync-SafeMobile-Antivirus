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
    internal const val EXTRA_SHA256 = "security.incident.detected_sha256"
    const val EXTRA_TEST_MODE = "security.incident.manual_test"

    fun ensureChannel(context: Context) {
        val local = com.vibesync.antivirus.core.locale.LocalePreferences.wrap(context)
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(NotificationChannel(
            CHANNEL_ID, local.getString(R.string.security_alert_channel_name), NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = local.getString(R.string.incident_channel_description)
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

    suspend fun notifyMaliciousApp(context: Context, packageName: String, eventId: String, sha256: String?) {
        if (com.vibesync.antivirus.core.security.TrustedAppStore(context).isTrusted(packageName)) return
        if (!runCatching { SystemPackageGuard.isUserInstalled(context, packageName) }.getOrDefault(false)) return
        val local = com.vibesync.antivirus.core.locale.LocalePreferences.wrap(context)
        show(local, eventId, local.getString(R.string.security_alert_malware_title),
            local.getString(R.string.security_alert_malware_body), packageName, R.string.voice_alert_malware_detected, true,
            sha256 = sha256)
    }

    suspend fun notifySuspiciousApp(context: Context, packageName: String, eventId: String) {
        if (com.vibesync.antivirus.core.security.TrustedAppStore(context).isTrusted(packageName)) return
        if (!runCatching { SystemPackageGuard.isUserInstalled(context, packageName) }.getOrDefault(false)) return
        val local = com.vibesync.antivirus.core.locale.LocalePreferences.wrap(context)
        show(local, eventId, local.getString(R.string.security_alert_review_title),
            local.getString(R.string.security_alert_review_body), null, R.string.voice_app_review, false)
    }

    /**
     * Explicit user-initiated AUDIO/NOTIFICATION diagnostic. Does not fabricate a malware verdict,
     * mark any app as infected, insert an incident row, or bypass production hash verification.
     * Returns its unique test event id for a foreground-only preview activity.
     */
    fun runManualSirenTest(context: Context): String {
        val eventId = "manual-siren-test-" + java.util.UUID.randomUUID().toString()
        Log.d(TAG, "Manual siren test requested by user, event=$eventId")
        show(context, eventId, context.getString(R.string.siren_test_title),
            context.getString(R.string.siren_test_notification), null,
            R.string.voice_siren_test, confirmed = true, testMode = true)
        return eventId
    }

    internal fun runInstallSirenDiagnostic(context: Context, eventId: String) {
        val local = com.vibesync.antivirus.core.locale.LocalePreferences.wrap(context)
        Log.e(TAG, "Install receiver diagnostic: five-second test alarm; no malware verdict event=$eventId")
        show(local, eventId, local.getString(R.string.siren_test_title),
            local.getString(R.string.siren_test_notification), null, R.string.voice_siren_test,
            confirmed = true, testMode = true)
    }

    private fun show(context: Context, eventId: String, title: String, body: String,
                     packageName: String?, voiceResource: Int, confirmed: Boolean,
                     testMode: Boolean = false, sha256: String? = null) {
        val app = context.applicationContext
        SecurityVoiceAlert.speakIfEnabled(app, voiceResource)
        val enabled = app.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)
        if (!enabled && !testMode) return
        InstallScanNotifications.escalated(eventId)
        if (confirmed && InstallScanNotifications.claimAlarm(eventId)) {
            Log.d(TAG, if (testMode) "Manual siren playback start" else "Verified threat siren playback start")
            SecurityIncidentSiren.start(app)
        }
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(app,
                Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            Log.w(TAG, "Notification permission denied; opt-in local audio remains available")
            return
        }
        ensureChannel(app)
        val open = if (confirmed && (packageName != null || testMode)) {
            Intent(app, ThreatDetectedActivity::class.java)
                .putExtra(ThreatDetectedActivity.EXTRA_PACKAGE, packageName)
                .putExtra(EXTRA_TEST_MODE, testMode)
        } else Intent(app, MainActivity::class.java).putExtra(EXTRA_OPEN_QUARANTINE, true)
        if (confirmed && sha256?.matches(Regex("[0-9a-fA-F]{64}")) == true) {
            open.putExtra(EXTRA_SHA256, sha256.lowercase())
        }
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
        if (confirmed && (packageName != null || testMode) &&
            FullScreenAlertAccess.isGranted(app)) {
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

    internal fun notificationId(eventId: String): Int = 710_000 + (eventId.hashCode() and 0x000F_FFFF)
    private const val TAG = "SafeMobileSecurityAlert"
}

class SecurityAlertDismissReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        SecurityAlertNotifier.dismiss(context, intent.getStringExtra(SecurityAlertNotifier.EXTRA_EVENT_ID))
    }
}

