package com.vibesync.antivirus.core.observer

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.SystemClock
import android.util.Log
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.security.TrustedAppStore
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import com.vibesync.antivirus.core.worker.MultiLayerScanWorker
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import java.util.UUID

/** Protected system package events are identical for Play, browsers and messaging installers. */
class PackageInstallReceiver(
    private val dispatchLive: ((String, String, Boolean) -> Boolean)? = null
) : BroadcastReceiver() {
 override fun onReceive(context: Context, intent: Intent) {
  if (intent.action != Intent.ACTION_PACKAGE_ADDED && intent.action != Intent.ACTION_PACKAGE_REPLACED) return
  val name = packageFrom(intent.data)
  Log.e(TAG, "Install broadcast action=${intent.action} package=$name replacing=${intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)}")
  if (name == null) { Log.e(TAG, "Ignored install: missing or invalid package URI"); return }
  val app = context.applicationContext
  if (!app.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
      .getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)) {
   Log.e(TAG, "Install received but privacy disclosure has not been accepted")
   return
  }
  if (name == app.packageName) return
  // An update emits both ADDED(replacing) and REPLACED. Process only the latter.
  if (intent.action == Intent.ACTION_PACKAGE_ADDED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
  val updated = intent.action == Intent.ACTION_PACKAGE_REPLACED
  if (!claim(name, updated)) { Log.d(TAG, "Duplicate install delivery coalesced"); return }
  val eventId = UUID.randomUUID().toString()
  val pending = goAsync()
  val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  scope.launch {
   try {
    withTimeout(8_000L) {
     val trusted = TrustedAppStore(app).isTrusted(name)
     InstallScanNotifications.received(app, label(app, name), eventId, trusted)
     if (trusted) { Log.d(TAG, "Trusted package: engines, siren and threat alerts bypassed"); return@withTimeout }
     if (!TrustedPackageWhitelist.isEligibleForReview(app, name)) {
      InstallScanNotifications.finish(app, eventId)
      Log.d(TAG, "Protected or unavailable package: no consumer scan")
      return@withTimeout
     }
     if (InstallDiagnosticPolicy.shouldTest(name, BuildConfig.DEBUG) &&
         (BuildConfig.DEBUG || harmlessFixture(app, name))) {
      SecurityAlertNotifier.runInstallSirenDiagnostic(app, eventId)
      // Diagnostic audio never exempts this reserved identity from ordinary analysis.
     }
     val request = OneTimeWorkRequestBuilder<MultiLayerScanWorker>().setInputData(
      Data.Builder().putString(MultiLayerScanWorker.KEY_PACKAGE_NAME, name)
       .putString(MultiLayerScanWorker.KEY_EVENT_ID, eventId)
       .putBoolean(MultiLayerScanWorker.KEY_UPDATED, updated).build()
     ).addTag("post_install_scan").build()
     // Durability first; the live service and worker share an idempotent serial processor.
     WorkManager.getInstance(app).enqueueUniqueWork("post_install:$eventId", ExistingWorkPolicy.KEEP, request)
     val live = dispatchLive?.invoke(name, eventId, updated) == true
     Log.e(TAG, "Post-install analysis queued event=$eventId liveSentinel=$live")
    }
   } catch (error: Exception) { Log.e(TAG, "Install dispatch failed before analysis could be queued", error) }
   finally { pending.finish(); scope.cancel() }
  }
 }

 private fun label(context: Context, name: String): String = runCatching {
  @Suppress("DEPRECATION")
  context.packageManager.getApplicationLabel(context.packageManager.getApplicationInfo(name, 0)).toString()
 }.getOrDefault(name)

 /** Release diagnostics accept only the reserved, component-free no-code fixture. */
 @Suppress("DEPRECATION")
 private fun harmlessFixture(context: Context, name: String): Boolean = runCatching {
  if (name != InstallDiagnosticPolicy.FIXTURE_PACKAGE) return@runCatching false
  val info = context.packageManager.getPackageInfo(name, PackageManager.GET_ACTIVITIES or
   PackageManager.GET_SERVICES or PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS or
   PackageManager.GET_INSTRUMENTATION)
  val flags = info.applicationInfo?.flags ?: return@runCatching false
  flags and ApplicationInfo.FLAG_HAS_CODE == 0 && info.activities.isNullOrEmpty() &&
   info.services.isNullOrEmpty() && info.receivers.isNullOrEmpty() &&
   info.providers.isNullOrEmpty() && info.instrumentation.isNullOrEmpty()
 }.getOrDefault(false)

 companion object {
  private const val TAG = "SafeMobileScan"
  private val received = LinkedHashMap<String, Long>()
  internal fun packageFrom(uri: Uri?): String? = uri?.takeIf { it.scheme == "package" }
   ?.schemeSpecificPart?.removePrefix("//")?.takeIf {
    it.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))
   }
  @Synchronized private fun claim(name: String, updated: Boolean): Boolean {
   val now = SystemClock.elapsedRealtime()
   val key = "$name:$updated"
   if (received[key]?.let { now - it < 2_000L } == true) return false
   received[key] = now
   while (received.size > 256) received.remove(received.keys.first())
   return true
  }
 }
}

