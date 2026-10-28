package com.vibesync.antivirus.core.observer

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.LocalePreferences

/** Silent delivery proof; escalation replaces this same event's notification on the alert channel. */
internal object InstallScanNotifications {
    private const val CHANNEL = "install_scan_progress_v1"
    private val alerts = LinkedHashSet<String>()
    private val alarms = InstallAlarmGate()
    fun claimAlarm(eventId: String): Boolean = alarms.claim(eventId)

    @Synchronized fun escalated(eventId: String) {
        alerts.add(eventId)
        while (alerts.size > 256) alerts.remove(alerts.first())
    }
    @Synchronized private fun wasEscalated(eventId: String) = eventId in alerts

    fun received(context: Context, label: String, eventId: String, trusted: Boolean = false) {
        val local = LocalePreferences.wrap(context)
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(NotificationChannel(CHANNEL,
            local.getString(R.string.install_sentinel_title), NotificationManager.IMPORTANCE_LOW).apply {
            setSound(null, null); enableVibration(false)
        })
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(context,
                Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            Log.e("SafeMobileScan", "Install received but POST_NOTIFICATIONS is denied; delivery proof cannot be shown")
            return
        }
        val pending = PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val title = if (trusted) local.getString(R.string.trusted_app_saved)
            else local.getString(R.string.install_scan_progress, label.take(120))
        val notification = NotificationCompat.Builder(local, CHANNEL).setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle(title).setContentText(if (trusted) label.take(120) else local.getString(R.string.scan_preparing))
            .setStyle(NotificationCompat.BigTextStyle().bigText(title))
            .setContentIntent(pending).setSilent(true).setOnlyAlertOnce(true).setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE).setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(NotificationCompat.PRIORITY_LOW).setTimeoutAfter(if (trusted) 10_000L else 120_000L)
            .build()
        runCatching { manager.notify(SecurityAlertNotifier.notificationId(eventId), notification) }
            .onSuccess { Log.d("SafeMobileScan", "Install delivery notification posted event=$eventId trusted=$trusted") }
            .onFailure { Log.e("SafeMobileScan", "Install delivery notification blocked", it) }
    }

    /** Keep delivery proof visible briefly, even for fast clean scans. Never overwrite an alert. */
    fun finish(context: Context, eventId: String) {
        if (wasEscalated(eventId)) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val id = SecurityAlertNotifier.notificationId(eventId)
        runCatching {
            val receipt = manager.activeNotifications.firstOrNull { it.id == id && it.notification.channelId == CHANNEL }
            if (receipt != null) {
                val local = LocalePreferences.wrap(context)
                val text = local.getString(R.string.install_scan_received)
                val notification = android.app.Notification.Builder.recoverBuilder(local, receipt.notification)
                    .setContentText(text).setStyle(android.app.Notification.BigTextStyle().bigText(text))
                    .setOnlyAlertOnce(true).setTimeoutAfter(15_000L).build()
                manager.notify(id, notification)
            }
        }.onFailure { Log.w("SafeMobileScan", "Unable to clear install progress", it) }
    }
}
