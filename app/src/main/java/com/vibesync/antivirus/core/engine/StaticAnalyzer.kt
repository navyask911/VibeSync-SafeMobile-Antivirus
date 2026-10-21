package com.vibesync.antivirus.core.engine
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.vibesync.antivirus.core.heuristics.PermissionRiskAnalyzer

data class StaticAnalysisResult(
 val packageName: String, val requestedPermissions: Set<String>, val topRiskPermissions: List<String>,
 val permissionFeatures: FloatArray, val hasAccessibilityService: Boolean, val apkPath: String?,
 val riskPoints: Int, val reasons: List<String>
)
/** Manifest-only analysis. It never reads messages, accessibility events or screen contents. */
class StaticAnalyzer(context: Context) {
 private val pm = context.applicationContext.packageManager
 fun analyze(packageName: String): StaticAnalysisResult? {
  if (packageName.isBlank()) return null
  val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
  val info = try {
   if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
   else { @Suppress("DEPRECATION"); pm.getPackageInfo(packageName, flags) }
  } catch (_: PackageManager.NameNotFoundException) { return null } catch (_: SecurityException) { return null }
  val permissions = info.requestedPermissions?.toSet().orEmpty()
  val accessibility = info.services.orEmpty().any { it.permission == PermissionRiskAnalyzer.BIND_ACCESSIBILITY }
  val features = FloatArray(RANKED.size) { index -> if (RANKED[index].permission in permissions) 1f else 0f }
  val present = RANKED.filter { it.permission in permissions }
  val top = present.sortedByDescending { it.weight }.take(30).map { it.permission }
  var points = present.sumOf { it.weight }
  val reasons = mutableListOf<String>()
  top.take(8).forEach { reasons += "Requests sensitive permission: " + it }
  if (accessibility) { points += 15; reasons += "Declares an AccessibilityService" }
  if (accessibility && PermissionRiskAnalyzer.SYSTEM_ALERT in permissions) {
   points += 40; reasons += "Requests AccessibilityService plus SYSTEM_ALERT_WINDOW"
  }
  if (PermissionRiskAnalyzer.RECEIVE_BOOT in permissions && PermissionRiskAnalyzer.READ_SMS in permissions && PermissionRiskAnalyzer.INTERNET in permissions) {
   points += 25; reasons += "Combines boot persistence, READ_SMS, and INTERNET"
  }
  if (PermissionRiskAnalyzer.REQUEST_INSTALL in permissions) {
   val source = runCatching {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) pm.getInstallSourceInfo(packageName).initiatingPackageName
    else { @Suppress("DEPRECATION"); pm.getInstallerPackageName(packageName) }
   }.getOrNull()
   if (source in BROWSERS || source in MESSENGERS) { points += 35; reasons += "Requests REQUEST_INSTALL_PACKAGES and source attribution names " + source }
  }
  return StaticAnalysisResult(packageName, permissions, top, features, accessibility, info.applicationInfo?.sourceDir, points.coerceIn(0,100), reasons.distinct())
 }
 private data class RankedPermission(val permission: String, val weight: Int)
 companion object {
  private val RANKED = listOf(
   RankedPermission("android.permission.SYSTEM_ALERT_WINDOW",20),RankedPermission("android.permission.REQUEST_INSTALL_PACKAGES",20),
   RankedPermission("android.permission.READ_SMS",18),RankedPermission("android.permission.RECEIVE_SMS",15),
   RankedPermission("android.permission.SEND_SMS",15),RankedPermission("android.permission.READ_CALL_LOG",15),
   RankedPermission("android.permission.WRITE_CALL_LOG",15),RankedPermission("android.permission.PROCESS_OUTGOING_CALLS",12),
   RankedPermission("android.permission.READ_PHONE_STATE",10),RankedPermission("android.permission.READ_PHONE_NUMBERS",10),
   RankedPermission("android.permission.CALL_PHONE",10),RankedPermission("android.permission.RECORD_AUDIO",10),
   RankedPermission("android.permission.MANAGE_EXTERNAL_STORAGE",10),RankedPermission("android.permission.READ_CONTACTS",8),
   RankedPermission("android.permission.WRITE_CONTACTS",8),RankedPermission("android.permission.CAMERA",8),
   RankedPermission("android.permission.ACCESS_FINE_LOCATION",8),RankedPermission("android.permission.RECEIVE_BOOT_COMPLETED",8),
   RankedPermission("android.permission.QUERY_ALL_PACKAGES",8),RankedPermission("android.permission.READ_EXTERNAL_STORAGE",6),
   RankedPermission("android.permission.WRITE_EXTERNAL_STORAGE",6),RankedPermission("android.permission.GET_ACCOUNTS",5),
   RankedPermission("android.permission.ACCESS_COARSE_LOCATION",5),RankedPermission("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",5),
   RankedPermission("android.permission.READ_CALENDAR",3),RankedPermission("android.permission.WRITE_CALENDAR",3),
   RankedPermission("android.permission.INTERNET",2),RankedPermission("android.permission.FOREGROUND_SERVICE",2),
   RankedPermission("android.permission.BIND_ACCESSIBILITY_SERVICE",15),RankedPermission("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",12)
  )
  private val BROWSERS = setOf("com.android.chrome","org.mozilla.firefox","com.microsoft.emmx","com.brave.browser","com.opera.browser","com.sec.android.app.sbrowser")
  private val MESSENGERS = setOf("com.whatsapp","org.telegram.messenger","com.facebook.orca","com.viber.voip","com.discord","com.skype.raider")
 }
}
