package com.vibesync.antivirus.core.observer
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File

class StorageSentinelService : Service() {
 private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
 private var observer: FileObserver? = null
 override fun onCreate() {
  super.onCreate()
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
   getSystemService(NotificationManager::class.java).createNotificationChannel(
    NotificationChannel(CHANNEL, getString(R.string.service_channel_name), NotificationManager.IMPORTANCE_LOW).apply { description = getString(R.string.service_channel_description) })
  }
  val notificationBuilder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL) else {
   @Suppress("DEPRECATION") Notification.Builder(this)
  }
  startForeground(NOTIFICATION_ID, notificationBuilder.setSmallIcon(R.drawable.ic_launcher)
   .setContentTitle(getString(R.string.service_notification_title)).setContentText(getString(R.string.service_notification_body)).setOngoing(true).build())
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) { stopSelf(); return }
  val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
  if (downloads.isDirectory) observer = object : FileObserver(downloads.absolutePath, CLOSE_WRITE or MOVED_TO or CREATE) {
   override fun onEvent(event: Int, path: String?) {
    if (path.isNullOrBlank() || !path.endsWith(".apk", true)) return
    scope.launch { (application as SafeMobileApp).repository.scanFile(File(downloads, path)) }
   }
  }.also { it.startWatching() }
 }
 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_NOT_STICKY
 override fun onDestroy() { observer?.stopWatching(); observer = null; scope.cancel(); super.onDestroy() }
 override fun onBind(intent: Intent?): IBinder? = null
 companion object { private const val CHANNEL = "safe_mobile_storage_sentinel"; private const val NOTIFICATION_ID = 7021 }
}
