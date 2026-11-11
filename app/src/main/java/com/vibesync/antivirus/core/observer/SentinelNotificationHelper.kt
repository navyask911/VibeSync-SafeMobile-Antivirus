package com.vibesync.antivirus.core.observer
import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.R
object SentinelNotificationHelper {
 const val SERVICE_CHANNEL="safe_mobile_sentinel_service";const val ALERT_CHANNEL="safe_mobile_sentinel_alerts";const val SERVICE_ID=7021
 fun ensureChannels(c:Context){if(Build.VERSION.SDK_INT<26)return;val m=c.getSystemService(NotificationManager::class.java)?:return;m.createNotificationChannel(NotificationChannel(SERVICE_CHANNEL,c.getString(R.string.service_channel_name),NotificationManager.IMPORTANCE_LOW));m.createNotificationChannel(NotificationChannel(ALERT_CHANNEL,c.getString(R.string.notification_sentinel_channel),NotificationManager.IMPORTANCE_HIGH))}
 fun foreground(c:Context):Notification{ensureChannels(c);val p=PendingIntent.getActivity(c,SERVICE_ID,NotificationDeepLinkContract.intent(c,NotificationDeepLinkContract.TYPE_SERVICE,null,null),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE);return NotificationCompat.Builder(c,SERVICE_CHANNEL).setSmallIcon(R.drawable.ic_launcher).setContentTitle(c.getString(R.string.notification_service_title)).setContentText(c.getString(R.string.notification_service_body)).setContentIntent(p).setOngoing(true).setOnlyAlertOnce(true).setCategory(NotificationCompat.CATEGORY_SERVICE).build()}
 fun malicious(c:Context,name:String?,removed:Boolean,id:String,fileUri:Uri?=null)=alert(c,if(removed)R.string.notification_blocked_title else R.string.notification_detected_title,if(removed)R.string.notification_blocked_body else R.string.notification_detected_body,name,null,id,NotificationDeepLinkContract.TYPE_DOWNLOAD_MALICIOUS,true,fileUri)
 fun review(c:Context,name:String?,id:String,fileUri:Uri?=null)=alert(c,R.string.notification_review_title,R.string.notification_review_body,name,null,id,NotificationDeepLinkContract.TYPE_DOWNLOAD_REVIEW,false,fileUri)
 fun quarantined(c:Context,name:String?,removed:Boolean,id:String,fileUri:Uri?=null)=alert(c,if(removed)R.string.notification_quarantine_title else R.string.notification_detected_title,if(removed)R.string.notification_quarantine_body else R.string.notification_detected_body,name,null,id,NotificationDeepLinkContract.TYPE_DOWNLOAD_QUARANTINED,false,fileUri)
 private fun alert(c:Context,title:Int,bodyId:Int,name:String?,installer:String?,id:String,kind:String,confirmed:Boolean,fileUri:Uri?){
  if(Build.VERSION.SDK_INT>=33&&ContextCompat.checkSelfPermission(c,Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED)return
  ensureChannels(c);val target=NotificationDeepLinkContract.intent(c,kind,fileUri?.toString(),id)
  val pi=PendingIntent.getActivity(c,id.hashCode(),target,PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE);val body=c.getString(bodyId)
  val n=NotificationCompat.Builder(c,ALERT_CHANNEL).setSmallIcon(R.drawable.ic_launcher).setContentTitle(c.getString(title)).setContentText(body).setStyle(NotificationCompat.BigTextStyle().bigText(if(name.isNullOrBlank())body else body+" ("+name.take(120)+")")).setContentIntent(pi).setPriority(NotificationCompat.PRIORITY_HIGH).setAutoCancel(true).build()
  // Full-screen intents are restricted by Android policy, so the high-priority content intent is the fallback.
  runCatching{NotificationManagerCompat.from(c).notify(id.hashCode(),n)}.onFailure{android.util.Log.w("SafeMobileSentinelNotify","Notification failed",it)}
 }
}
