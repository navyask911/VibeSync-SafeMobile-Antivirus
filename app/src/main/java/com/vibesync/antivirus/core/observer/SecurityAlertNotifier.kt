package com.vibesync.antivirus.core.observer

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioAttributes
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R

/**
 * High-priority, local security notifications. Channel sound is configured once by Android;
 * users retain control over sound and vibration in system notification settings.
 */
object SecurityAlertNotifier {
    const val CHANNEL_ID = "security_alert_high_alarm_v2"
    const val EXTRA_OPEN_QUARANTINE = "com.vibesync.antivirus.OPEN_QUARANTINE"

    fun ensureChannel(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val sound = Uri.parse("android.resource://${context.packageName}/${R.raw.security_alert_siren}")
        val audio = AudioAttributes.Builder()
            .setUsage(AudioAttributes.USAGE_ALARM)
            .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
            .build()
        val channel = NotificationChannel(
            CHANNEL_ID,
            context.getString(R.string.security_alert_channel_name),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = context.getString(R.string.security_alert_channel_description)
            lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
            setSound(sound, audio)
            enableVibration(true)
            enableLights(true)
        }
        manager.createNotificationChannel(channel)
    }

    /** Called only after an encrypted quarantine copy has been durably written and verified. */
    fun notifyQuarantinedFile(context: Context, fileName: String, eventId: String, confirmedMalicious: Boolean) {
        val spoken = if (confirmedMalicious) {
            "Warning. A malicious app was detected and quarantined."
        } else {
            "Warning. A suspicious file was isolated in SafeMobile's encrypted quarantine."
        }
        show(
            context, eventId,
            context.getString(R.string.security_alert_file_title),
            context.getString(R.string.security_alert_file_body, fileName.take(100)),
            uninstallPackage = null,
            spokenText = spoken
        )
    }

    /** Normal Android apps cannot remove another installed package without user/system action. */
    fun notifyMaliciousApp(context: Context, packageName: String, eventId: String) {
        show(
            context, eventId,
            context.getString(R.string.security_alert_malware_title),
            context.getString(R.string.security_alert_malware_body),
            uninstallPackage = packageName,
            spokenText = "Warning. A malicious app was detected after installation. Review or uninstall it now."
        )
    }

    fun notifySuspiciousApp(context: Context, packageName: String, eventId: String) {
        show(
            context, eventId,
            context.getString(R.string.security_alert_review_title),
            context.getString(R.string.security_alert_review_body),
            uninstallPackage = packageName,
            spokenText = "Warning. A newly installed app needs security review."
        )
    }

    private fun show(
        context: Context,
        eventId: String,
        title: String,
        body: String,
        uninstallPackage: String?,
        spokenText: String
    ) {
        val app = context.applicationContext
        // Voice alerts are independent from notification permission, but still explicitly opt-in.
        SecurityVoiceAlert.speakIfEnabled(app, spokenText)
        val securityPrefs = app.getSharedPreferences(com.vibesync.antivirus.SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
        if (!securityPrefs.getBoolean(com.vibesync.antivirus.SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)) return
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(app, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return

        ensureChannel(app)
        val openVault = Intent(app, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            putExtra(EXTRA_OPEN_QUARANTINE, true)
        }
        val immutable = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        val contentIntent = PendingIntent.getActivity(app, eventId.hashCode(), openVault, immutable)
        val notification = NotificationCompat.Builder(app, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setContentIntent(contentIntent)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .addAction(R.drawable.ic_launcher, app.getString(R.string.security_alert_open_vault), contentIntent)
            .apply {
                if (!uninstallPackage.isNullOrBlank() && uninstallPackage != app.packageName) {
                    val uninstall = Intent(
                        Intent.ACTION_DELETE,
                        Uri.fromParts("package", uninstallPackage, null)
                    )
                    val uninstallIntent = PendingIntent.getActivity(
                        app, eventId.hashCode() xor 0x4A31, uninstall, immutable
                    )
                    addAction(R.drawable.ic_launcher, app.getString(R.string.security_alert_uninstall), uninstallIntent)
                }
            }
            .build()
        runCatching {
            NotificationManagerCompat.from(app).notify(notificationId(eventId), notification)
        }.onFailure {
            android.util.Log.w(TAG, "Unable to post local security alert", it)
        }
    }

    private fun notificationId(eventId: String): Int = 710_000 + (eventId.hashCode() and 0x000F_FFFF)
    private const val TAG = "SafeMobileSecurityAlert"
}
