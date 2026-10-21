package com.vibesync.antivirus.core.observer

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.io.File

class StorageSentinelService : Service() {
 private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
 private var observer: FileObserver? = null
 private val recentEvents = LinkedHashMap<String, Long>()

 override fun onCreate() {
  super.onCreate()
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
   getSystemService(NotificationManager::class.java).createNotificationChannel(
    NotificationChannel(CHANNEL, getString(R.string.service_channel_name), NotificationManager.IMPORTANCE_LOW).apply {
     description = getString(R.string.service_channel_description)
    }
   )
  }
  val notificationBuilder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
   Notification.Builder(this, CHANNEL)
  } else {
   @Suppress("DEPRECATION") Notification.Builder(this)
  }
  startForeground(NOTIFICATION_ID, notificationBuilder.setSmallIcon(R.drawable.ic_launcher)
   .setContentTitle(getString(R.string.service_notification_title))
   .setContentText(getString(R.string.service_notification_body)).setOngoing(true).build())

  if (!hasStorageAccess()) {
   stopSelf()
   return
  }
  @Suppress("DEPRECATION")
  val downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
  if (!downloads.isDirectory && !downloads.mkdirs()) {
   stopSelf()
   return
  }
  if (!downloads.isDirectory) {
   stopSelf()
   return
  }
  observer = object : FileObserver(downloads.absolutePath, CLOSE_WRITE or MOVED_TO) {
   override fun onEvent(event: Int, path: String?) {
    if ((event and CLOSE_WRITE) == 0 && (event and MOVED_TO) == 0) return
    if (path.isNullOrBlank() || !path.endsWith(".apk", ignoreCase = true)) return
    val file = File(downloads, path)
    if (!shouldProcess(file)) return
    scope.launch {
     try {
      if (waitUntilStable(file)) {
       (application as SafeMobileApp).repository.scanFile(file)
      }
     } catch (cancelled: CancellationException) {
      throw cancelled
     } catch (_: Exception) {
      // A transient filesystem or permission failure is reflected by the missing scan result.
      // Never log file paths or automatically remove/disable the file.
     }
    }
   }
  }.also { it.startWatching() }
 }

 private fun hasStorageAccess(): Boolean =
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
   runCatching { Environment.isExternalStorageManager() }.getOrDefault(false)
  } else {
   checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
  }

 private fun shouldProcess(file: File): Boolean {
  val path = runCatching { file.canonicalPath }.getOrDefault(file.absolutePath)
  val now = System.currentTimeMillis()
  synchronized(recentEvents) {
   val previous = recentEvents.put(path, now)
   recentEvents.entries.removeIf { now - it.value > EVENT_TTL_MS }
   while (recentEvents.size > MAX_RECENT_EVENTS) {
    val iterator = recentEvents.entries.iterator()
    if (iterator.hasNext()) {
     iterator.next()
     iterator.remove()
    } else break
   }
   previous == null || now - previous >= DEDUPE_WINDOW_MS
  }.let { return it }
 }

 private suspend fun waitUntilStable(file: File): Boolean {
  var previousSize = -1L
  var previousModified = -1L
  var stableSamples = 0
  repeat(STABILITY_ATTEMPTS) {
   currentCoroutineContext().ensureActive()
   if (!file.isFile || !file.canRead()) return false
   val size = file.length()
   val modified = file.lastModified()
   if (size == previousSize && modified == previousModified) stableSamples++ else stableSamples = 0
   if (stableSamples >= REQUIRED_STABLE_SAMPLES) return true
   previousSize = size
   previousModified = modified
   delay(STABILITY_DELAY_MS)
  }
  return false
 }

 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
  if (!hasStorageAccess()) {
   stopSelf(startId)
   return START_NOT_STICKY
  }
  return START_NOT_STICKY
 }
 override fun onDestroy() {
  observer?.stopWatching()
  observer = null
  synchronized(recentEvents) { recentEvents.clear() }
  scope.cancel()
  super.onDestroy()
 }
 override fun onBind(intent: Intent?): IBinder? = null

 companion object {
  private const val CHANNEL = "safe_mobile_storage_sentinel"
  private const val NOTIFICATION_ID = 7021
  private const val DEDUPE_WINDOW_MS = 8_000L
  private const val EVENT_TTL_MS = 60_000L
  private const val MAX_RECENT_EVENTS = 256
  private const val STABILITY_DELAY_MS = 450L
  private const val STABILITY_ATTEMPTS = 7
  private const val REQUIRED_STABLE_SAMPLES = 2
 }
}
