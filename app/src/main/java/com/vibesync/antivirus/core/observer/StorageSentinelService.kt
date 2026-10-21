package com.vibesync.antivirus.core.observer
import android.Manifest
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.IBinder
import android.util.Log
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.local.SecurityIncidentEntity
import com.vibesync.antivirus.data.local.QuarantineVaultEntity
import java.io.File
import java.io.IOException
import java.util.LinkedHashMap
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
class StorageSentinelService:Service(){
 private val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO);private var fileObserver:FileObserver?=null;private var media:DownloadSentinelObserver?=null;private val recent=LinkedHashMap<String,Long>()
 override fun onCreate(){super.onCreate();SentinelNotificationHelper.ensureChannels(this);startForeground(SentinelNotificationHelper.SERVICE_ID,SentinelNotificationHelper.foreground(this));val prefs=getSharedPreferences(SafeMobileApp.SECURITY_PREFS,MODE_PRIVATE);if(!prefs.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED,false)||!AccessibilityGuardStatus.isGuardActive(this)||!hasStorage()){stopSelf();return}
  @Suppress("DEPRECATION") val downloads=Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);if(!downloads.isDirectory&&!downloads.mkdirs()){stopSelf();return};if(!downloads.isDirectory){stopSelf();return}
  fileObserver=object:FileObserver(downloads.absolutePath,CLOSE_WRITE or MOVED_TO or MODIFY){override fun onEvent(event:Int,path:String?){if((event and CLOSE_WRITE)==0&&(event and MOVED_TO)==0&&(event and MODIFY)==0)return;if(path.isNullOrBlank()||!candidate(path))return;val f=File(downloads,path);if(!shouldProcess(f.name,f.length(),f.lastModified()))return;scope.launch{try{if(waitStable(f))processFile(f)}catch(c:CancellationException){throw c}catch(_:SecurityException){Log.w(TAG,"Downloads access denied")}catch(_:IOException){Log.w(TAG,"Downloads processing failed")}}}}.also{it.startWatching()}
  media=DownloadSentinelObserver(this){row->if(!shouldProcess(row.displayName,row.size,row.dateModifiedSeconds))return@DownloadSentinelObserver;scope.launch{try{delay(900L);currentCoroutineContext().ensureActive();processUri(row.uri,row.displayName,row.relativePath)}catch(c:CancellationException){throw c}catch(_:SecurityException){Log.w(TAG,"MediaStore access denied")}catch(_:IOException){Log.w(TAG,"MediaStore processing failed")}}}.also{it.register()}
 }
 private fun candidate(n:String)=n.endsWith(".apk",true)||n.endsWith(".exe",true)
 private fun hasStorage()=if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.R)runCatching{Environment.isExternalStorageManager()}.getOrDefault(false)else checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)==PackageManager.PERMISSION_GRANTED
 private fun shouldProcess(name:String,size:Long,modified:Long):Boolean{val k=name.take(180).lowercase()+":"+size+":"+modified;val now=System.currentTimeMillis();synchronized(recent){val prev=recent.put(k,now);recent.entries.removeIf{now-it.value>90000L};while(recent.size>256){val it=recent.entries.iterator();if(it.hasNext()){it.next();it.remove()}else break};return prev==null||now-prev>=10000L}}
 private suspend fun waitStable(f:File):Boolean{var size=-1L;var mod=-1L;var stable=0;repeat(8){currentCoroutineContext().ensureActive();if(!f.isFile||!f.canRead())return false;val s=f.length();val m=f.lastModified();if(s==size&&m==mod)stable++else stable=0;if(stable>=2)return true;size=s;mod=m;delay(450L)};return false}
 private suspend fun processFile(f:File){if(!f.isFile||!f.canRead())return;val r=(application as SafeMobileApp).repository.scanFile(f);process(r,f.name,"Downloads/"+f.name,f,null)}
 private suspend fun processUri(uri:Uri,name:String,rel:String?){val r=(application as SafeMobileApp).repository.scanUri(uri);process(r,name,((rel?:"Shared storage/")+name).take(180),null,uri)}
 private suspend fun process(r:ScanResult,name:String,path:String,file:File?,uri:Uri?){val app=application as SafeMobileApp;val p=getSharedPreferences(SafeMobileApp.SECURITY_PREFS,MODE_PRIVATE);val strict=p.getBoolean(SafeMobileApp.KEY_STRICT_MODE,false);val malicious=DownloadSentinelPolicy.isConfirmedMalicious(r.verdict);val quarantine=DownloadSentinelPolicy.shouldQuarantine(r.verdict,strict);val id=UUID.randomUUID().toString()
  val reason=when{malicious->"local_sha256_match";r.verdict==ScanVerdict.NOT_SCANNED->"hash_unavailable";strict->"strict_mode_unverified_download";r.verdict==ScanVerdict.SUSPICIOUS->"suspicious_scan_result";else->"no_local_signature_match_unverified"};var removed=false;var action="NOT_QUARANTINED";var status="REVIEW_REQUIRED";var saved:File?=null
  if(quarantine){try{val outcome=when{file!=null->app.repository.quarantineObservedDownload(file,r.sha256);uri!=null->app.repository.quarantineObservedDownload(uri,r.sha256);else->null};saved=outcome?.privateCopy;removed=outcome?.originalRemoved==true;action=if(removed)"MOVED_TO_ENCRYPTED_VAULT"else"ENCRYPTED_COPY_ONLY";status=if(removed)"QUARANTINED"else"SOURCE_RETAINED_COPY_SAVED";if(!removed&&saved!=null){for(wait in longArrayOf(700L,1500L,3000L)){delay(wait);currentCoroutineContext().ensureActive();val ok=when{file!=null->app.repository.retryRemoveObservedDownload(file);uri!=null->app.repository.retryRemoveObservedDownload(uri);else->false};if(ok){removed=true;action="MOVED_TO_ENCRYPTED_VAULT";status="QUARANTINED";break}}};if(saved==null){action="QUARANTINE_FAILED";status="SOURCE_RETAINED"}}catch(c:CancellationException){throw c}catch(_:IOException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine failed; source retained")}catch(_:java.security.GeneralSecurityException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine cryptographic key unavailable; source retained")}catch(_:SecurityException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine access denied; source retained")}catch(_:IllegalArgumentException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine candidate rejected")}}
  if(saved!=null){val vault=QuarantineVaultEntity(saved.name,System.currentTimeMillis(),name.take(120),path.take(180),r.sha256?.takeIf{it.matches(Regex("(?i)^[0-9a-f]{64}$"))},null,saved.absolutePath.take(500),reason,if(removed)"QUARANTINED"else"COPY_SAVED_SOURCE_RETAINED");runCatching{app.database.quarantineVaultDao().insert(vault)}.onFailure{Log.w(TAG,"Quarantine vault metadata insert failed",it)}}
  val event=SecurityIncidentEntity(id,System.currentTimeMillis(),"DOWNLOAD",null,null,name.take(120),r.sha256?.takeIf{it.matches(Regex("(?i)^[0-9a-f]{64}$"))},path.take(180),reason,action,status);runCatching{app.database.securityIncidentDao().insert(event)}.onFailure{Log.w(TAG,"Incident insert failed",it)}
  when{malicious->SentinelNotificationHelper.malicious(this,name,removed,id);quarantine->SentinelNotificationHelper.quarantined(this,name,removed,id);else->SentinelNotificationHelper.review(this,name,id)}
 }
 override fun onStartCommand(intent:Intent?,flags:Int,startId:Int):Int{val p=getSharedPreferences(SafeMobileApp.SECURITY_PREFS,MODE_PRIVATE);if(!p.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED,false)||!AccessibilityGuardStatus.isGuardActive(this)||!hasStorage()){stopSelf(startId);return START_NOT_STICKY};return START_STICKY}
 override fun onDestroy(){fileObserver?.stopWatching();fileObserver=null;media?.close();media=null;synchronized(recent){recent.clear()};scope.cancel();super.onDestroy()}
 override fun onBind(intent:Intent?):IBinder?=null
 companion object{private const val TAG="SafeMobileSentinel"}
}
