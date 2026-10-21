package com.vibesync.antivirus.core.observer
import android.app.BroadcastReceiver
import android.app.PendingIntent
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import android.app.NotificationChannel
import android.app.NotificationManager
import com.vibesync.antivirus.R
class UninstallStatusReceiver:BroadcastReceiver(){
 override fun onReceive(context:Context,intent:Intent?){if(intent==null)return;val status=intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE);if(status==PackageInstaller.STATUS_PENDING_USER_ACTION){val confirmation=if(Build.VERSION.SDK_INT>=33)intent.getParcelableExtra(Intent.EXTRA_INTENT,Intent::class.java)else{@Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_INTENT) as? Intent}?:return;confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);try{context.startActivity(confirmation)}catch(e:ActivityNotFoundException){notify(context,confirmation)}catch(e:SecurityException){notify(context,confirmation)}}else if(status!=PackageInstaller.STATUS_SUCCESS)Log.w(TAG,"Uninstall did not complete; user may retry")}
 private fun notify(c:Context,confirmation:Intent){if(Build.VERSION.SDK_INT>=26)c.getSystemService(NotificationManager::class.java)?.createNotificationChannel(NotificationChannel(CHANNEL,c.getString(R.string.notification_sentinel_channel),NotificationManager.IMPORTANCE_HIGH));val pi=PendingIntent.getActivity(c,9137,confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE);val n=NotificationCompat.Builder(c,CHANNEL).setSmallIcon(R.drawable.ic_launcher).setContentTitle(c.getString(R.string.uninstall_launch_failed)).setContentText(c.getString(R.string.activity_not_found_action)).setContentIntent(pi).setPriority(NotificationCompat.PRIORITY_HIGH).setAutoCancel(true).build();runCatching{NotificationManagerCompat.from(c).notify(9137,n)}.onFailure{Log.w(TAG,"Uninstall fallback notification failed",it)}}
 companion object{const val EXTRA_PACKAGE_NAME="target_package_name";private const val TAG="SafeMobileUninstallStatus";private const val CHANNEL="safe_mobile_uninstall_status"}
}
