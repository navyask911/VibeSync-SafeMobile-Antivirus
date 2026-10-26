package com.vibesync.antivirus.core.observer

import android.app.Service
import android.content.Intent
import android.net.Uri
import android.os.IBinder
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.observer.SecurityAlertNotifier
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
 private val privateTextStore by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { EncryptedHashStore(applicationContext) }

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
            while (currentCoroutineContext().isActive) {
                try {
                    val roots = StorageAccessPreferences.accessibleTreeUris(this@StorageSentinelService)
                    if (roots.isEmpty()) { stopSelf(); break }
                    var visited = 0
                    for (child in SafTreeWalker.files(this@StorageSentinelService, roots)) {
                        currentCoroutineContext().ensureActive()
                        if (++visited % 128 == 0) delay(25L)
                        try {
                            val name = child.name?.take(180).orEmpty()
                            if (!candidate(name)) continue
                            val size = child.length()
                            val modified = child.lastModified()
                            val identity = child.uri.toString()
                            if (!shouldProcess(identity, size, modified)) continue
                            delay(FILE_SETTLE_DELAY_MS)
                            if (!child.exists() || !child.canRead() || child.length() != size || child.lastModified() != modified) continue
                            val result = (application as SafeMobileApp).repository.scanUri(child.uri)
                            if (!(application as SafeMobileApp).repository.isReviewableResult(result)) {
                                rememberProcessed(identity, size, modified)
                                continue
                            }
                            if (result.verdict != ScanVerdict.NOT_SCANNED) {
                                process(result, name, name, null, child.uri)
                                rememberProcessed(identity, size, modified)
                            }
                        } catch (cancelled: CancellationException) { throw cancelled }
                        catch (failure: Exception) { Log.w(TAG, "Granted file scan failed; continuing with other files", failure) }
                    }
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (failure: Exception) { Log.w(TAG, "Folder sweep failed; retrying without losing saved grants", failure) }
                delay(POLL_INTERVAL_MS)
            }
        }
    }

 private fun candidate(n:String)=n.endsWith(".apk",true)||n.endsWith(".exe",true)
 private fun hasStorage() = StorageAccessPreferences.hasAccess(this)
 private fun shouldProcess(uri: String, size: Long, modified: Long): Boolean = synchronized(recent) {
    val key = "$uri:$size:$modified"
    val seen = recent[key] ?: return@synchronized true
    // Providers without a modification timestamp are periodically rechecked.
    modified == 0L && System.currentTimeMillis() - seen >= 60_000L
 }
 private fun rememberProcessed(uri: String, size: Long, modified: Long) = synchronized(recent) {
    recent["$uri:$size:$modified"] = System.currentTimeMillis()
    while (recent.size > 4096) { val iterator = recent.entries.iterator(); iterator.next(); iterator.remove() }
 }
 private suspend fun process(r:ScanResult,name:String,path:String,file:File?,uri:Uri?){val app=application as SafeMobileApp;val p=getSharedPreferences(SafeMobileApp.SECURITY_PREFS,MODE_PRIVATE);val strict=p.getBoolean(SafeMobileApp.KEY_STRICT_MODE,false);val malicious=DownloadSentinelPolicy.isConfirmedMalicious(r.verdict);val quarantine=DownloadSentinelPolicy.shouldQuarantine(r.verdict,strict);val id=UUID.randomUUID().toString()
  val reason=when{malicious->"local_sha256_match";r.verdict==ScanVerdict.NOT_SCANNED->"hash_unavailable";strict->"strict_mode_unverified_download";r.verdict==ScanVerdict.SUSPICIOUS->"suspicious_scan_result";else->"no_local_signature_match_unverified"};var removed=false;var action="NOT_QUARANTINED";var status="REVIEW_REQUIRED";var saved:File?=null
  if(quarantine){try{val outcome=when{file!=null->app.repository.quarantineObservedDownload(file,r.sha256);uri!=null->app.repository.quarantineObservedDownload(uri,r.sha256);else->null};saved=outcome?.privateCopy;removed=outcome?.originalRemoved==true;action=if(removed)"MOVED_TO_ENCRYPTED_VAULT"else"ENCRYPTED_COPY_ONLY";status=if(removed)"QUARANTINED"else"SOURCE_RETAINED_COPY_SAVED";if(!removed&&saved!=null){for(wait in longArrayOf(700L,1500L,3000L)){delay(wait);currentCoroutineContext().ensureActive();val ok=when{file!=null->app.repository.retryRemoveObservedDownload(file);uri!=null->app.repository.retryRemoveObservedDownload(uri);else->false};if(ok){removed=true;action="MOVED_TO_ENCRYPTED_VAULT";status="QUARANTINED";break}}};if(saved==null){action="QUARANTINE_FAILED";status="SOURCE_RETAINED"}}catch(c:CancellationException){throw c}catch(_:IOException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine failed; source retained")}catch(_:java.security.GeneralSecurityException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine cryptographic key unavailable; source retained")}catch(_:SecurityException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine access denied; source retained")}catch(_:IllegalArgumentException){action="QUARANTINE_FAILED";status="SOURCE_RETAINED";Log.w(TAG,"Quarantine candidate rejected")}}
  if(saved!=null){val vault=QuarantineVaultEntity(saved.name,System.currentTimeMillis(),
   privateTextStore.protectPrivateText(name.take(120), "vault-filename"),
   privateTextStore.protectPrivateText(path.take(180), "vault-path"),
   r.sha256?.takeIf{it.matches(Regex("(?i)^[0-9a-f]{64}$"))},null,
   privateTextStore.protectPrivateText(saved.absolutePath.take(500), "vault-copy-path"),
   reason,if(removed)"QUARANTINED"else"COPY_SAVED_SOURCE_RETAINED");runCatching{app.database.quarantineVaultDao().insert(vault)}.onFailure{Log.w(TAG,"Quarantine vault metadata insert failed",it)}}
  val event=SecurityIncidentEntity(id,System.currentTimeMillis(),"DOWNLOAD",null,null,
   privateTextStore.protectPrivateText(name.take(120), "incident-filename"),
   r.sha256?.takeIf{it.matches(Regex("(?i)^[0-9a-f]{64}$"))},
   privateTextStore.protectPrivateText(path.take(180), "incident-path"),
   privateTextStore.protectPrivateText(reason, "incident-reason"),action,status);runCatching{app.database.securityIncidentDao().insert(event)}.onFailure{Log.w(TAG,"Incident insert failed",it)}
  if(saved!=null && (malicious || r.verdict==ScanVerdict.SUSPICIOUS)) {
    // Audible/high-priority alert only after encrypted quarantine content was successfully saved.
    SecurityAlertNotifier.notifyQuarantinedFile(this,name,id,malicious)
   } else {
    when{malicious->SentinelNotificationHelper.malicious(this,name,removed,id);quarantine->SentinelNotificationHelper.quarantined(this,name,removed,id);else->SentinelNotificationHelper.review(this,name,id)}
   }
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
 }
}

