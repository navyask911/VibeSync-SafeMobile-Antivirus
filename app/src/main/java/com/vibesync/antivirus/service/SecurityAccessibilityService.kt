package com.vibesync.antivirus.service
import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.observer.AccessibilityGuardStatus
import com.vibesync.antivirus.core.observer.InstallerUiDetector
import com.vibesync.antivirus.core.observer.SentinelNotificationHelper
import com.vibesync.antivirus.core.observer.ThreatBlockedActivity
import com.vibesync.antivirus.data.local.SecurityIncidentEntity
import java.util.ArrayDeque
import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
/** Opt-in best-effort guard; it inspects only known installer-window nodes. */
class SecurityAccessibilityService:AccessibilityService(){
 private val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO);private val handler=Handler(Looper.getMainLooper());@Volatile private var lastIntercept=0L
 override fun onServiceConnected(){super.onServiceConnected();serviceInfo=(serviceInfo?:AccessibilityServiceInfo()).apply{eventTypes=AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED or AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED;feedbackType=AccessibilityServiceInfo.FEEDBACK_GENERIC;notificationTimeout=100;flags=flags or AccessibilityServiceInfo.FLAG_REPORT_VIEW_IDS}}
 override fun onAccessibilityEvent(e:AccessibilityEvent?){if(e==null||(e.eventType!=AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED&&e.eventType!=AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED))return;if(!AccessibilityGuardStatus.isGuardActive(this))return;val pkg=e.packageName?.toString()?:return;if(!InstallerUiDetector.isInstallerPackage(pkg))return;val root=runCatching{rootInActiveWindow}.getOrNull()?:return;if(!InstallerUiDetector.isInstallerPackage(root.packageName?.toString()?:pkg))return;val result=inspect(root);if(!result.apk)return;val now=System.currentTimeMillis();synchronized(this){if(now-lastIntercept<4000L)return;lastIntercept=now};interruptAndLog(pkg,result.filename,result.cancelClicked)}
 private fun inspect(root:AccessibilityNodeInfo):Evidence{val queue=ArrayDeque<AccessibilityNodeInfo>();queue.add(root);var count=0;var apk=false;var name:String?=null;var clicked=false
  while(queue.isNotEmpty()&&count<220){val node=queue.removeFirst();count++;try{val text=node.text?.toString()?.take(240).orEmpty();val desc=node.contentDescription?.toString()?.take(240).orEmpty();val id=node.viewIdResourceName?.take(180);val values=listOf(text,desc).filter{it.isNotBlank()};if(!apk){apk=InstallerUiDetector.isApkInstallUi(values);if(apk)name=values.firstNotNullOfOrNull(InstallerUiDetector::extractApkFilename)};if(!clicked&&(InstallerUiDetector.isCancelControl(text,id)||InstallerUiDetector.isCancelControl(desc,id))&&node.isClickable&&node.isEnabled)clicked=runCatching{node.performAction(AccessibilityNodeInfo.ACTION_CLICK)}.getOrDefault(false);if(apk&&name==null)name=values.firstNotNullOfOrNull(InstallerUiDetector::extractApkFilename);for(i in 0 until node.childCount)runCatching{node.getChild(i)}.getOrNull()?.let(queue::addLast)}catch(_:RuntimeException){Log.d(TAG,"Installer node expired")}}
  return Evidence(apk,name,clicked)}
 private fun interruptAndLog(pkg:String,name:String?,clicked:Boolean){runCatching{performGlobalAction(GLOBAL_ACTION_BACK)}.onFailure{Log.d(TAG,"BACK action unavailable")};handler.postDelayed({
  val still=runCatching{rootInActiveWindow?.packageName?.toString()}.getOrNull().let(InstallerUiDetector::isInstallerPackage);if(still)runCatching{performGlobalAction(GLOBAL_ACTION_BACK)}.onFailure{Log.d(TAG,"Retry BACK unavailable")}
  val id=UUID.randomUUID().toString();val event=SecurityIncidentEntity(id,System.currentTimeMillis(),"INSTALL_PROMPT",pkg.take(160),null,name?.take(120),null,null,"installer_apk_confirmation_ui",if(clicked)"CANCEL_CLICK_AND_BACK" else "BACK_ATTEMPTED",if(still)"INTERRUPTION_UNCONFIRMED" else "WINDOW_DISMISSED_BEST_EFFORT")
  scope.launch{val app=application as SafeMobileApp;runCatching{app.database.securityIncidentDao().insert(event)}.onFailure{Log.w(TAG,"Incident persistence failed",it)};SentinelNotificationHelper.installInterrupted(this@SecurityAccessibilityService,pkg,name,id)}
  val intent=Intent(this,ThreatBlockedActivity::class.java).apply{addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP);putExtra(ThreatBlockedActivity.EXTRA_EVENT_KIND,"INSTALL_PROMPT");putExtra(ThreatBlockedActivity.EXTRA_FILENAME,name?.take(120));putExtra(ThreatBlockedActivity.EXTRA_INSTALLER,pkg.take(160));putExtra(ThreatBlockedActivity.EXTRA_REASON,"installer_apk_confirmation_ui");putExtra(ThreatBlockedActivity.EXTRA_EVENT_ID,id);putExtra(ThreatBlockedActivity.EXTRA_CONFIRMED_MALICIOUS,false)}
  runCatching{startActivity(intent)}.onFailure{Log.w(TAG,"Background launch restricted; notification fallback available",it)}
 },350L)}
 override fun onInterrupt()=Unit
 override fun onDestroy(){handler.removeCallbacksAndMessages(null);scope.cancel();super.onDestroy()}
 private data class Evidence(val apk:Boolean,val filename:String?,val cancelClicked:Boolean)
 companion object{private const val TAG="SafeMobileAccessibility"}
}
