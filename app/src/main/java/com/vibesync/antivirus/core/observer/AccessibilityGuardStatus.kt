package com.vibesync.antivirus.core.observer
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.vibesync.antivirus.SafeMobileApp
object AccessibilityGuardStatus {
 fun isEnabledInSystemSettings(context:Context):Boolean {
  val c=ComponentName(context,com.vibesync.antivirus.service.SecurityAccessibilityService::class.java);val flat=c.flattenToString();val short=c.flattenToShortString()
  val secure=runCatching{Settings.Secure.getString(context.contentResolver,Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES).orEmpty().split(':').any{it.equals(flat,true)||it.equals(short,true)}}.getOrDefault(false)
  val manager=runCatching{(context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager)?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)?.any{it.id.equals(flat,true)||it.id.equals(short,true)}==true}.getOrDefault(false)
  return secure||manager
 }
 fun isOptedIn(context:Context)=context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS,Context.MODE_PRIVATE).getBoolean(SafeMobileApp.KEY_ACCESSIBILITY_GUARD_OPT_IN,false)
 fun isGuardActive(context:Context)=isOptedIn(context)&&isEnabledInSystemSettings(context)
}
