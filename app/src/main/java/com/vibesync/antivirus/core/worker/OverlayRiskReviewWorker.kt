package com.vibesync.antivirus.core.worker

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import java.util.concurrent.TimeUnit

/**
 * Best-effort declaration review. This worker cannot observe whether another app is actively
 * displaying an overlay or determine another package's live overlay AppOp state.
 */
class OverlayRiskReviewWorker(
 context: Context,
 params: WorkerParameters
) : CoroutineWorker(context, params) {

 override suspend fun doWork(): Result {
  val prefs = applicationContext.getSharedPreferences(OverlayRiskReviewManager.PREFS_NAME, Context.MODE_PRIVATE)
  if (!prefs.getBoolean(OverlayRiskReviewManager.KEY_ENABLED, false)) return Result.success()

  prefs.edit().putLong(OverlayRiskReviewManager.KEY_LAST_ATTEMPT, System.currentTimeMillis()).apply()
  return try {
   val packages = applicationContext.packageManager.getInstalledPackages(
    PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
   ).filter { info ->
    info.applicationInfo?.let { app ->
     com.vibesync.antivirus.core.security.ProtectedPackagePolicy.isUserInstalled(app.flags, info.packageName, applicationContext.packageName)
    } == true
   }
   val overlayDeclarations = packages.count { info ->
    info.requestedPermissions?.contains(OVERLAY_PERMISSION) == true
   }
   val accessibilityDeclarations = packages.count { info ->
    info.services.orEmpty().any { service ->
     service.permission == ACCESSIBILITY_SERVICE_PERMISSION
    }
   }
   val reviewablePackageNames = packages.mapTo(hashSetOf()) { it.packageName }
   val accessibilityManager = applicationContext.getSystemService(AccessibilityManager::class.java)
    ?: throw IllegalStateException("Accessibility service metadata unavailable")
   val enabledAccessibilityServices = accessibilityManager
    .getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
    .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
    .filter(reviewablePackageNames::contains)
    .distinct()
    .size

   val now = System.currentTimeMillis()
   prefs.edit()
    .putLong(OverlayRiskReviewManager.KEY_LAST_SUCCESS, now)
    .putInt(OverlayRiskReviewManager.KEY_OVERLAY_DECLARATIONS, overlayDeclarations)
    .putInt(OverlayRiskReviewManager.KEY_ACCESSIBILITY_DECLARATIONS, accessibilityDeclarations)
    .putInt(OverlayRiskReviewManager.KEY_ENABLED_ACCESSIBILITY_SERVICES, enabledAccessibilityServices)
    .putString(OverlayRiskReviewManager.KEY_RESULT, "AVAILABLE")
    .apply()

   maybeNotify(
    prefs = prefs,
    overlayDeclarations = overlayDeclarations,
    accessibilityDeclarations = accessibilityDeclarations
   )
   Result.success()
  } catch (_: SecurityException) {
   prefs.edit().putString(OverlayRiskReviewManager.KEY_RESULT, "PERMISSION_REQUIRED").apply()
   Result.success()
  } catch (_: Exception) {
   prefs.edit().putString(OverlayRiskReviewManager.KEY_RESULT, "FAILED").apply()
   if (runAttemptCount < MAX_RETRIES) Result.retry() else Result.failure()
  }
 }

 private fun maybeNotify(
  prefs: android.content.SharedPreferences,
  overlayDeclarations: Int,
  accessibilityDeclarations: Int
 ) {
  val context = applicationContext
  val intervalHours = prefs.getInt(OverlayRiskReviewManager.KEY_REMINDER_HOURS, DEFAULT_REMINDER_HOURS)
  val now = System.currentTimeMillis()
  val lastReminder = prefs.getLong(OverlayRiskReviewManager.KEY_LAST_REMINDER, 0L)
  if (now - lastReminder < TimeUnit.HOURS.toMillis(intervalHours.toLong())) return
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
   ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
  ) return
  if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) return

  val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
   notificationManager.createNotificationChannel(
    NotificationChannel(
     CHANNEL_ID,
     context.getString(R.string.overlay_review_notification_channel),
     NotificationManager.IMPORTANCE_LOW
    ).apply { description = context.getString(R.string.overlay_review_notification_channel_description) }
   )
  }
  val openApp = PendingIntent.getActivity(
   context,
   NOTIFICATION_REQUEST_CODE,
   Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
   PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
  )
  val notification = NotificationCompat.Builder(context, CHANNEL_ID)
   .setSmallIcon(R.drawable.ic_launcher)
   .setContentTitle(context.getString(R.string.overlay_review_notification_title))
   .setContentText(context.getString(
    R.string.overlay_review_notification_body,
    overlayDeclarations,
    accessibilityDeclarations
   ))
   .setContentIntent(openApp)
   .setAutoCancel(true)
   .setOnlyAlertOnce(true)
   .setPriority(NotificationCompat.PRIORITY_LOW)
   .build()
  runCatching {
   NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
   prefs.edit().putLong(OverlayRiskReviewManager.KEY_LAST_REMINDER, now).apply()
  }
 }

 companion object {
  private const val OVERLAY_PERMISSION = "android.permission.SYSTEM_ALERT_WINDOW"
  private const val ACCESSIBILITY_SERVICE_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"
  private const val MAX_RETRIES = 2
  private const val DEFAULT_REMINDER_HOURS = 24
  private const val CHANNEL_ID = "safe_mobile_overlay_review"
  private const val NOTIFICATION_ID = 7042
  private const val NOTIFICATION_REQUEST_CODE = 7042
 }
}

object OverlayRiskReviewManager {
 const val PREFS_NAME = "safe_mobile_overlay_review"
 const val KEY_ENABLED = "enabled"
 const val KEY_LAST_ATTEMPT = "last_attempt_ms"
 const val KEY_LAST_SUCCESS = "last_success_ms"
 const val KEY_OVERLAY_DECLARATIONS = "overlay_declaration_count"
 const val KEY_ACCESSIBILITY_DECLARATIONS = "accessibility_declaration_count"
 const val KEY_ENABLED_ACCESSIBILITY_SERVICES = "enabled_accessibility_services_count"
 const val KEY_REMINDER_HOURS = "reminder_interval_hours"
 const val KEY_LAST_REMINDER = "last_reminder_ms"
 const val KEY_RESULT = "result_state"

 private const val PERIODIC_WORK = "safe_mobile_overlay_risk_review_periodic"
 private const val FOREGROUND_WORK = "safe_mobile_overlay_risk_review_foreground"

 fun isEnabled(context: Context): Boolean =
  context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).getBoolean(KEY_ENABLED, false)

 fun setEnabled(context: Context, enabled: Boolean) {
  val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
  prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()
  val workManager = WorkManager.getInstance(context)
  if (!enabled) {
   workManager.cancelUniqueWork(PERIODIC_WORK)
   workManager.cancelUniqueWork(FOREGROUND_WORK)
   return
  }
  val constraints = Constraints.Builder().setRequiresBatteryNotLow(true).build()
  val periodic = PeriodicWorkRequestBuilder<OverlayRiskReviewWorker>(12, TimeUnit.HOURS)
   .setConstraints(constraints)
   .build()
  workManager.enqueueUniquePeriodicWork(PERIODIC_WORK, ExistingPeriodicWorkPolicy.UPDATE, periodic)
  requestForegroundReview(context)
 }

 fun setReminderIntervalHours(context: Context, hours: Int) {
  require(hours == 12 || hours == 24 || hours == 48) { "Reminder interval must be 12, 24, or 48 hours." }
  context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
   .edit().putInt(KEY_REMINDER_HOURS, hours).apply()
 }

 fun requestForegroundReview(context: Context) {
  if (!isEnabled(context)) return
  val request = OneTimeWorkRequestBuilder<OverlayRiskReviewWorker>()
   .setConstraints(Constraints.Builder().setRequiresBatteryNotLow(true).build())
   .build()
  WorkManager.getInstance(context).enqueueUniqueWork(FOREGROUND_WORK, ExistingWorkPolicy.KEEP, request)
 }
}

