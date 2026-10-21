package com.vibesync.antivirus.presentation
import android.app.PendingIntent
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import android.util.Log
import android.net.Uri
import com.vibesync.antivirus.core.observer.UninstallStatusReceiver
sealed class UninstallResult { object Success:UninstallResult();object RequiresUserAction:UninstallResult();data class BlockedSystemApp(val reason:String):UninstallResult();object NotFound:UninstallResult();object OpenedAppInfo:UninstallResult();object HandlerUnavailable:UninstallResult() }
object UninstallHandler {
 private const val TAG="SafeMobileUninstall"
 fun buildDeleteIntent(packageName:String)=Intent(Intent.ACTION_DELETE,Uri.parse("package:"+requireValidPackage(packageName))).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
 fun buildAppInfoIntent(packageName:String)=Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+requireValidPackage(packageName))).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
 fun request(context:Context,packageName:String,launchDelete:(Intent)->Unit,openAppInfo:(Intent)->Unit):UninstallResult{
  val pkg=SystemPackageGuard.normalizePackageName(packageName)?:return UninstallResult.NotFound
  when(val guard=SystemPackageGuard.evaluate(context,pkg)){is PackageGuardResult.BlockedSystemApp->return UninstallResult.BlockedSystemApp(guard.reason);PackageGuardResult.NotFound->return UninstallResult.NotFound;PackageGuardResult.Allowed->Unit}
  // PackageInstaller.uninstall is only attempted for SafeMobile's own installed-package provenance.
  if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.O){
   val installer=runCatching{context.packageManager.getInstallSourceInfo(pkg).installingPackageName}.getOrNull()
   if(installer==context.packageName){
    val callback=Intent(context,UninstallStatusReceiver::class.java).setAction("com.vibesync.antivirus.UNINSTALL_STATUS").putExtra(UninstallStatusReceiver.EXTRA_PACKAGE_NAME,pkg)
    val flags=PendingIntent.FLAG_UPDATE_CURRENT or (if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.S)PendingIntent.FLAG_MUTABLE else 0)
    try{val pi=PendingIntent.getBroadcast(context,pkg.hashCode(),callback,flags);context.packageManager.packageInstaller.uninstall(pkg,pi.intentSender);return UninstallResult.RequiresUserAction}
    catch(e:SecurityException){Log.w(TAG,"PackageInstaller denied; using ACTION_DELETE",e)}
    catch(e:IllegalArgumentException){Log.w(TAG,"PackageInstaller rejected target; using ACTION_DELETE",e)}
    catch(e:UnsupportedOperationException){Log.w(TAG,"PackageInstaller not supported; using ACTION_DELETE",e)}
   }
  }
  return launchFallback(pkg,launchDelete,openAppInfo)
 }
 fun launchWithFallback(packageName:String,launchDelete:(Intent)->Unit,openAppInfo:(Intent)->Unit):UninstallResult{
  val p=SystemPackageGuard.normalizePackageName(packageName)?:return UninstallResult.NotFound
  return launchFallback(p,launchDelete,openAppInfo)
 }
 private fun launchFallback(pkg:String,launchDelete:(Intent)->Unit,openAppInfo:(Intent)->Unit):UninstallResult=try{launchDelete(buildDeleteIntent(pkg));UninstallResult.RequiresUserAction}
 catch(e:ActivityNotFoundException){Log.w(TAG,"ACTION_DELETE unavailable; opening App Info",e);openSettings(pkg,openAppInfo)}
 catch(e:SecurityException){Log.w(TAG,"ACTION_DELETE blocked; opening App Info",e);openSettings(pkg,openAppInfo)}
 catch(e:IllegalStateException){Log.w(TAG,"Uninstall host not active; opening App Info",e);openSettings(pkg,openAppInfo)}
 catch(e:IllegalArgumentException){Log.w(TAG,"ACTION_DELETE rejected; opening App Info",e);openSettings(pkg,openAppInfo)}
 private fun openSettings(pkg:String,open:(Intent)->Unit):UninstallResult=try{open(buildAppInfoIntent(pkg));UninstallResult.OpenedAppInfo}
 catch(e:ActivityNotFoundException){Log.w(TAG,"App Info unavailable",e);UninstallResult.HandlerUnavailable}
 catch(e:SecurityException){Log.w(TAG,"App Info restricted",e);UninstallResult.HandlerUnavailable}
 catch(e:IllegalStateException){Log.w(TAG,"App Info host not active",e);UninstallResult.HandlerUnavailable}
 catch(e:IllegalArgumentException){Log.w(TAG,"App Info intent rejected",e);UninstallResult.HandlerUnavailable}
 private fun requireValidPackage(v:String)=SystemPackageGuard.normalizePackageName(v)?:throw IllegalArgumentException("Invalid package name")
}
