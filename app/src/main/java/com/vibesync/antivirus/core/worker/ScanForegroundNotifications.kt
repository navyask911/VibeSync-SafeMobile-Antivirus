package com.vibesync.antivirus.core.worker

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.ForegroundInfo
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R

/** Persistent, user-visible notification shared by long-running local scan workers. */
object ScanForegroundNotifications {
    const val CHANNEL_ID = "safe_mobile_scan_foreground_v1"

    fun create(context: Context, notificationId: Int): ForegroundInfo {
        val manager = context.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.scan_foreground_channel_name),
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = context.getString(R.string.scan_foreground_channel_description)
                    // The high-importance channel is visible without producing repetitive scan noise.
                    setSound(null, null)
                    enableVibration(false)
                }
            )
        }

        val openApp = PendingIntent.getActivity(
            context,
            notificationId,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle(context.getString(R.string.scan_foreground_notification_title))
            .setContentText(context.getString(R.string.scan_foreground_notification_body))
            .setContentIntent(openApp)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()

        val serviceType = if (Build.VERSION.SDK_INT >= 34) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        return ForegroundInfo(notificationId, notification, serviceType)
    }

    fun notificationId(workId: java.util.UUID): Int {
        // Keep concurrently running workers' foreground notification IDs distinct and positive.
        return 7_200_000 + kotlin.math.abs(workId.hashCode() % 100_000)
    }
}
