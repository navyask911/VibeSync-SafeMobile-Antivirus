package com.vibesync.antivirus.core.observer

import android.app.Service
import android.content.Intent
import android.net.Uri
import android.os.IBinder
import android.util.Log
import androidx.documentfile.provider.DocumentFile
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
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * User-enabled SAF folder monitor. It polls the persisted, user-selected directory instead of
 * requesting MANAGE_EXTERNAL_STORAGE or reading the public shared-storage filesystem directly.
 */
class StorageSentinelService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val recent = LinkedHashMap<String, Long>()

    override fun onCreate() {
        super.onCreate()
        SentinelNotificationHelper.ensureChannels(this)
        startForeground(SentinelNotificationHelper.SERVICE_ID, SentinelNotificationHelper.foreground(this))
        val prefs = getSharedPreferences(SafeMobileApp.SECURITY_PREFS, MODE_PRIVATE)
        if (!prefs.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false) || !hasStorage()) {
            stopSelf()
            return
        }
        scope.launch {
            try {
                while (currentCoroutineContext().isActive) {
                    val treeUri = StorageAccessPreferences.selectedTreeUri(this@StorageSentinelService)
                    val root = treeUri?.let { DocumentFile.fromTreeUri(this@StorageSentinelService, it) }
                    if (root == null || !root.canRead()) {
                        Log.w(TAG, "Selected SAF folder is no longer available; stopping monitor")
                        stopSelf()
                        break
                    }
                    scanDirectory(root, root.name.orEmpty().ifBlank { "Selected folder" }, 0, intArrayOf(MAX_ENTRIES_PER_PASS))
                    delay(POLL_INTERVAL_MS)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: SecurityException) {
                Log.w(TAG, "Selected SAF folder access was revoked", failure)
                stopSelf()
            } catch (failure: Exception) {
                Log.w(TAG, "SAF folder monitoring pass failed", failure)
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private suspend fun scanDirectory(directory: DocumentFile, relativePath: String, depth: Int, budget: IntArray) {
        currentCoroutineContext().ensureActive()
        if (budget[0] <= 0 || !directory.canRead()) return
        val children = runCatching { directory.listFiles() }.getOrElse {
            Log.w(TAG, "Could not list selected SAF folder", it)
            return
        }
        for (child in children) {
            currentCoroutineContext().ensureActive()
            if (budget[0]-- <= 0) break
            val name = child.name?.take(180).orEmpty()
            if (child.isDirectory && depth < MAX_DIRECTORY_DEPTH) {
                scanDirectory(child, relativePath + "/" + name, depth + 1, budget)
            } else if (child.isFile && candidate(name)) {
                val size = runCatching { child.length() }.getOrDefault(0L)
                val modified = runCatching { child.lastModified() }.getOrDefault(0L)
                if (shouldProcess(name, size, modified)) {
                    delay(FILE_SETTLE_DELAY_MS)
                    currentCoroutineContext().ensureActive()
                    if (child.exists() && child.canRead()) {
                        try {
                            processUri(child.uri, name, relativePath + "/")
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: SecurityException) {
                            Log.w(TAG, "Selected SAF file could not be opened")
                        } catch (failure: IOException) {
                            Log.w(TAG, "Selected SAF file processing failed")
                        }
                    }
                }
            }
        }
    }

 private fun candidate(n:String)=n.endsWith(".apk",true)||n.endsWith(".exe",true)
 private fun hasStorage() = StorageAccessPreferences.hasAccess(this)
 private fun shouldProcess(name:String,size:Long,modified:Long):Boolean{val k=name.take(180).lowercase()+":"+size+":"+modified;val now=System.currentTimeMillis();synchronized(recent){val prev=recent.put(k,now);recent.entries.removeIf{now-it.value>90000L};while(recent.size>256){val it=recent.entries.iterator();if(it.hasNext()){it.next();it.remove()}else break};return prev==null||now-prev>=10000L}}
 private suspend fun processUri(uri:Uri,name:String,rel:String?){val r=(application as SafeMobileApp).repository.scanUri(uri);process(r,name,((rel?:"Shared storage/")+name).take(180),null,uri)}
 private suspend fun process(r:ScanResult,name:String,path:String,file:File?,uri:Uri?){val app=application as SafeMobileApp;val p=getSharedPreferences(SafeMobileApp.SECURITY_PREFS,MODE_PRIVATE);val strict=p.getBoolean(SafeMobileApp.KEY_STRICT_MODE,false);val malicious=DownloadSentinelPolicy.isConfirmedMalicious(r.verdict);val quarantine=DownloadSentinelPolicy.shouldQuarantine(r.verdict,strict);val id=UUID.randomUUID().toString()
  val reason=when{malicious->"local_sha256_match";r.verdict==ScanVerdict.NOT_SCANNED->"hash_unavailable";strict->"strict_mode_unverified_download";r.verdict==ScanVerdict.SUSPICIOUS->"suspicious_scan_result";else->"no_local_signature_match_unverified"};var removed=false;var action="NOT_QUARANTINED";var status="REVIEW_REQUIRED";var saved:File?=null
  if(quarantine){try{val outcome=when{file!=null->app.repository.quarantineObservedDownload(file,r.sha256);uri!=null->app.repository.quarantineObservedDownload(uri,r.sha256);else->null};saved=outcome?.privateCopy;removed=outcome?.originalRemoved==true;action=if(removed)"MOVED_TO_ENCRYPTED_VAULT"else"ENCRYPTED_COPY_ONLY";status=if(removed)"QUARANTINED"else"SOURCE_RETAINED_COPY_SAVED";if(!removed&&saved!=null){for(wait in longArrayOf(700L,1500L,3000L)){delay(wait);currentCoroutineContext().ensureActive();val ok=when{file!=null->app.repository.retryRemoveObservedDownload(file);uri!=null->app.repository.retryRemoveObservedDownload(uri);else->false};if(ok){removed=true;action="MOVED_TO_ENCRYPTED_VAULT";status="QUARANTINED";break}}};if(saved==null){action="QUARANTINE_FAILED";status="SOURCE_RETAINED"}}catch(c:CancellationException){throw c}catch(_:IOException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine failed; source retained")}catch(_:java.security.GeneralSecurityException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine cryptographic key unavailable; source retained")}catch(_:SecurityException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine access denied; source retained")}catch(_:IllegalArgumentException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine candidate rejected")}}
  if(saved!=null){val vault=QuarantineVaultEntity(saved.name,System.currentTimeMillis(),name.take(120),path.take(180),r.sha256?.takeIf{it.matches(Regex("(?i)^[0-9a-f]{64}$"))},null,saved.absolutePath.take(500),reason,if(removed)"QUARANTINED"else"COPY_SAVED_SOURCE_RETAINED");runCatching{app.database.quarantineVaultDao().insert(vault)}.onFailure{Log.w(TAG,"Quarantine vault metadata insert failed",it)}}
  val event=SecurityIncidentEntity(id,System.currentTimeMillis(),"DOWNLOAD",null,null,name.take(120),r.sha256?.takeIf{it.matches(Regex("(?i)^[0-9a-f]{64}$"))},path.take(180),reason,action,status);runCatching{app.database.securityIncidentDao().insert(event)}.onFailure{Log.w(TAG,"Incident insert failed",it)}
  when{malicious->SentinelNotificationHelper.malicious(this,name,removed,id);quarantine->SentinelNotificationHelper.quarantined(this,name,removed,id);else->SentinelNotificationHelper.review(this,name,id)}
 }

 override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val prefs = getSharedPreferences(SafeMobileApp.SECURITY_PREFS, MODE_PRIVATE)
    if (!prefs.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false) || !hasStorage()) {
        stopSelf(startId)
        return START_NOT_STICKY
    }
    return START_STICKY
 }

 override fun onDestroy() {
    synchronized(recent) { recent.clear() }
    scope.cancel()
    super.onDestroy()
 }

 override fun onBind(intent: Intent?): IBinder? = null

 companion object {
    private const val TAG = "SafeMobileSentinel"
    private const val POLL_INTERVAL_MS = 4_000L
    private const val FILE_SETTLE_DELAY_MS = 800L
    private const val MAX_ENTRIES_PER_PASS = 500
    private const val MAX_DIRECTORY_DEPTH = 2
 }
}
