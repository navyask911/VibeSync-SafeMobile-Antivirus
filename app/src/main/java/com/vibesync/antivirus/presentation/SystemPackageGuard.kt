package com.vibesync.antivirus.presentation
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
sealed class PackageGuardResult { object Allowed:PackageGuardResult();data class BlockedSystemApp(val reason:String):PackageGuardResult();object NotFound:PackageGuardResult() }
object SystemPackageGuard {
 fun isSystemFlags(flags:Int)=flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)!=0
 fun evaluateFlags(flags:Int,isActiveDeviceAdmin:Boolean=false):PackageGuardResult =
  when { isSystemFlags(flags)->PackageGuardResult.BlockedSystemApp("system"); isActiveDeviceAdmin->PackageGuardResult.BlockedSystemApp("admin"); else->PackageGuardResult.Allowed }

 fun evaluate(context:Context,raw:String):PackageGuardResult{
  val pkg=normalizePackageName(raw)?:return PackageGuardResult.NotFound
  val pm=context.packageManager
  val info=try{@Suppress("DEPRECATION") pm.getApplicationInfo(pkg,0)}catch(_:PackageManager.NameNotFoundException){return PackageGuardResult.NotFound}catch(_:SecurityException){return PackageGuardResult.NotFound}
  if(isSystemFlags(info.flags)){if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.R)runCatching{pm.getInstallSourceInfo(pkg).installingPackageName};return PackageGuardResult.BlockedSystemApp("system")}
  val dpm=context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
  if(dpm!=null){val admins=runCatching{dpm.activeAdmins.orEmpty()}.getOrDefault(emptyList<ComponentName>());if(admins.any{it.packageName==pkg&&runCatching{dpm.isAdminActive(it)}.getOrDefault(false)})return PackageGuardResult.BlockedSystemApp("admin")}
  // A null installer can occur for legitimate sideloaded apps; never block it unless system flags identify a preinstalled package.
  if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.R)runCatching{pm.getInstallSourceInfo(pkg).installingPackageName}
  return PackageGuardResult.Allowed
 }
 fun normalizePackageName(value:String?):String?{val p=value?.trim()?:return null;if(p.isBlank()||p.length>255||!p.matches(Regex("^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+$")))return null;return p}
}
