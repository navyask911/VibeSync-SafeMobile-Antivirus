package com.vibesync.antivirus.core.observer

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R

object SentinelNotificationHelper {
    const val SERVICE_CHANNEL = "safe_mobile_sentinel_service_v2"
    const val ALERT_CHANNEL = "safe_mobile_sentinel_alerts"
    const val SERVICE_ID = 7021

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(SERVICE_CHANNEL, context.getString(R.string.service_channel_name), NotificationManager.IMPORTANCE_HIGH).apply {
                // Keep the always-on status visible without making routine service startup noisy.
                setSound(null, null)
                enableVibration(false)
            }
        )
        manager.createNotificationChannel(
            NotificationChannel(ALERT_CHANNEL, context.getString(R.string.notification_sentinel_channel), NotificationManager.IMPORTANCE_HIGH)
        )
    }

    fun foreground(context: Context): Notification {
        ensureChannels(context)
        val pending = PendingIntent.getActivity(
            context, SERVICE_ID,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(context, SERVICE_CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle(context.getString(R.string.notification_service_title))
            .setContentText(context.getString(R.string.notification_service_body))
            .setContentIntent(pending).setOngoing(true).setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_HIGH).build()
    }

    fun malicious(context: Context, name: String?, removed: Boolean, id: String,
                  fileUri: String? = null, path: String? = null, reason: String? = null) =
        alert(context,
            if (removed) R.string.notification_blocked_title else R.string.notification_detected_title,
            if (removed) R.string.notification_blocked_body else R.string.notification_detected_body,
            name, id, "DOWNLOAD_MALICIOUS", true, fileUri, path, reason)

    fun review(context: Context, name: String?, id: String,
               fileUri: String? = null, path: String? = null, reason: String? = null) =
        alert(context, R.string.notification_review_title, R.string.notification_review_body,
            name, id, "DOWNLOAD_REVIEW", false, fileUri, path, reason)

    fun quarantined(context: Context, name: String?, removed: Boolean, id: String,
                    fileUri: String? = null, path: String? = null, reason: String? = null) =
        alert(context,
            if (removed) R.string.notification_quarantine_title else R.string.notification_detected_title,
            if (removed) R.string.notification_quarantine_body else R.string.notification_detected_body,
            name, id, "DOWNLOAD_QUARANTINED", false, fileUri, path, reason)

    private fun alert(
        context: Context, titleId: Int, bodyId: Int, name: String?, id: String, kind: String,
        confirmed: Boolean, fileUri: String?, path: String?, reason: String?
    ) {
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(
                context, Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED) return
        ensureChannels(context)
        val target = Intent(context, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            if (fileUri != null) addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            putExtra(NotificationDeepLink.EXTRA_NOTIFICATION_TYPE, kind)
            putExtra(NotificationDeepLink.EXTRA_FILE_URI, fileUri)
            putExtra(NotificationDeepLink.EXTRA_LOG_ID, id)
            putExtra(NotificationDeepLink.EXTRA_FILE_NAME, name?.take(240))
            putExtra(NotificationDeepLink.EXTRA_FILE_PATH, (path ?: fileUri).orEmpty().take(4096))
            putExtra(NotificationDeepLink.EXTRA_REASON, reason ?: if (confirmed) "local_sha256_match" else "best_effort_review")
            data = fileUri?.takeIf { it.startsWith("content:") || it.startsWith("file:") }?.let(Uri::parse)
                ?: Uri.fromParts("safemobile-notification", id, null)
        }
        val pending = PendingIntent.getActivity(
            context, id.hashCode(), target,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val body = context.getString(bodyId)
        val notification = NotificationCompat.Builder(context, ALERT_CHANNEL)
            .setSmallIcon(R.drawable.ic_launcher).setContentTitle(context.getString(titleId))
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(if (name.isNullOrBlank()) body else "$body ($name)"))
            .setContentIntent(pending).setPriority(NotificationCompat.PRIORITY_HIGH).setAutoCancel(true).build()
        runCatching { NotificationManagerCompat.from(context).notify(id.hashCode(), notification) }
            .onFailure { android.util.Log.w("SafeMobileSentinelNotify", "Notification failed", it) }
    }
}
