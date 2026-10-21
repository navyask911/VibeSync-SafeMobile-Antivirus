package com.vibesync.antivirus.core.observer
import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
object InstallSourceNotifier {
 private const val CHANNEL = "safe_mobile_install_source_review"
 fun notify(context: Context,appName: String,source: String,eventId: String) {
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
   ContextCompat.checkSelfPermission(context,Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
  val manager = context.getSystemService(NotificationManager::class.java) ?: return
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) manager.createNotificationChannel(
   NotificationChannel(CHANNEL,context.getString(R.string.notification_install_source_channel),NotificationManager.IMPORTANCE_HIGH))
  val pending = PendingIntent.getActivity(context,eventId.hashCode(),
   Intent(context,MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
   PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  val body = context.getString(R.string.notification_install_source_body,appName,source)
  val notification = NotificationCompat.Builder(context,CHANNEL).setSmallIcon(R.drawable.ic_launcher)
   .setContentTitle(context.getString(R.string.notification_install_source_title)).setContentText(body)
   .setStyle(NotificationCompat.BigTextStyle().bigText(body)).setContentIntent(pending)
   .setPriority(NotificationCompat.PRIORITY_HIGH).setAutoCancel(true).build()
  runCatching { NotificationManagerCompat.from(context).notify(eventId.hashCode(),notification) }
 }
}
