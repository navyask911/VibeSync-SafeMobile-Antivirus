package com.vibesync.antivirus.core.worker
import android.app.Notification
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

object ScanForegroundNotifications {
 const val CHANNEL_ID = "safe_mobile_scan_foreground_v1"
 const val SERVICE_NOTIFICATION_ID = 7_210_001
 private fun ensureChannel(context: Context) {
  val manager = context.getSystemService(NotificationManager::class.java)
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) manager.createNotificationChannel(
   NotificationChannel(CHANNEL_ID, context.getString(R.string.scan_foreground_channel_name), NotificationManager.IMPORTANCE_HIGH).apply {
    description = context.getString(R.string.scan_foreground_channel_description)
    setSound(null, null); enableVibration(false)
   })
 }
 fun createService(context: Context): Notification {
  ensureChannel(context)
  val open = PendingIntent.getActivity(context, SERVICE_NOTIFICATION_ID,
   Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
   PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val stop = PendingIntent.getService(context, SERVICE_NOTIFICATION_ID + 1,
   Intent(context, ScanForegroundService::class.java).setAction(ScanForegroundService.ACTION_STOP),
   PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  return NotificationCompat.Builder(context, CHANNEL_ID)
   .setSmallIcon(R.drawable.ic_launcher)
   .setContentTitle(context.getString(R.string.scan_foreground_notification_title))
   .setContentText(context.getString(R.string.scan_foreground_notification_body))
   .setContentIntent(open)
   .addAction(android.R.drawable.ic_media_pause, context.getString(R.string.scan_stop_action), stop)
   .setOngoing(true).setOnlyAlertOnce(true).setCategory(NotificationCompat.CATEGORY_SERVICE)
   .setPriority(NotificationCompat.PRIORITY_HIGH).setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
   .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE).build()
 }
 fun serviceForegroundType(): Int = if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0
 fun create(context: Context, notificationId: Int): ForegroundInfo {
  ensureChannel(context)
  val open = PendingIntent.getActivity(context, notificationId,
   Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP),
   PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val n = NotificationCompat.Builder(context, CHANNEL_ID).setSmallIcon(R.drawable.ic_launcher)
   .setContentTitle(context.getString(R.string.scan_foreground_notification_title))
   .setContentText(context.getString(R.string.scan_foreground_notification_body))
   .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
   .setCategory(NotificationCompat.CATEGORY_SERVICE).setPriority(NotificationCompat.PRIORITY_HIGH)
   .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
   .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE).build()
  return ForegroundInfo(notificationId, n, serviceForegroundType())
 }
 fun notificationId(workId: java.util.UUID): Int = 7_200_000 + kotlin.math.abs(workId.hashCode() % 100_000)
}
