package com.vibesync.antivirus.core.security
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
data class IntegrityReport(val isUntrusted: Boolean, val reasons: List<String>)
/** Best-effort offline root/hook indicators; not cryptographic attestation and can be bypassed. */
class IntegrityChecker(context: Context) {
 private val app = context.applicationContext
 fun check(): IntegrityReport {
  val reasons = linkedSetOf<String>()
  if (Build.TAGS.orEmpty().contains("test-keys",true)) reasons += "Device build uses test-keys"
  ROOT_PATHS.filter { File(it).exists() }.forEach { reasons += "Root artifact path present: " + it }
  HOOK_PATHS.filter { File(it).exists() }.forEach { reasons += "Hook framework artifact path present: " + it }
  KNOWN_PACKAGES.filter { installed(it) }.forEach { reasons += "Root/hook management package visible: " + it }
  return IntegrityReport(reasons.isNotEmpty(), reasons.toList())
 }
 private fun installed(name: String): Boolean = try {
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) app.packageManager.getApplicationInfo(name,PackageManager.ApplicationInfoFlags.of(0L))
  else {
   @Suppress("DEPRECATION")
   app.packageManager.getApplicationInfo(name,0)
  }
  true
 } catch (_: PackageManager.NameNotFoundException) { false } catch (_: SecurityException) { false }
 companion object {
  private val ROOT_PATHS = listOf("/system/bin/su","/system/xbin/su","/sbin/su","/vendor/bin/su","/system/app/Superuser.apk","/data/adb/magisk","/sbin/.magisk","/data/adb/modules")
  private val HOOK_PATHS = listOf("/system/framework/XposedBridge.jar","/system/lib/libxposed_art.so","/system/lib64/libxposed_art.so","/data/adb/lspd","/data/adb/riru")
  private val KNOWN_PACKAGES = setOf("com.topjohnwu.magisk","eu.chainfire.supersu","com.koushikdutta.superuser","de.robv.android.xposed.installer","org.meowcat.edxposed.manager","com.saurik.substrate")
 }
}
