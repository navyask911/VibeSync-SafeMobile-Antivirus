package com.vibesync.antivirus.core.observer
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.SafeMobileApp
class SentinelBootReceiver:BroadcastReceiver(){
 override fun onReceive(context:Context,intent:Intent?){if(intent?.action!=Intent.ACTION_BOOT_COMPLETED)return;val app=context.applicationContext;val p=app.getSharedPreferences(SafeMobileApp.SECURITY_PREFS,Context.MODE_PRIVATE);if(!p.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED,false)||!p.getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED,false))return;runCatching{ContextCompat.startForegroundService(app,Intent(app,StorageSentinelService::class.java))}.onFailure{Log.w(TAG,"Android restricted Download Sentinel startup",it)}}
 companion object{private const val TAG="SafeMobileBootReceiver"}
}
