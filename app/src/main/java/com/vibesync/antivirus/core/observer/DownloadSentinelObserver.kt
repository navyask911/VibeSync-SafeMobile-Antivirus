package com.vibesync.antivirus.core.observer
import android.content.ContentUris
import android.content.Context
import android.database.ContentObserver
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.BaseColumns
import android.provider.MediaStore
import android.util.Log
import java.io.Closeable
import java.util.LinkedHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
data class DownloadCandidate(val uri:android.net.Uri,val id:Long,val displayName:String,val mimeType:String?,val relativePath:String?,val size:Long,val dateModifiedSeconds:Long)
/** MediaStore.Files observer; current rows are baselined so enabling does not rescan all files. */
class DownloadSentinelObserver(context:Context,private val onCandidate:(DownloadCandidate)->Unit):Closeable {
 private val resolver=context.applicationContext.contentResolver
 private val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO)
 private val handler=Handler(Looper.getMainLooper())
 private val lock=Any();private val seen=LinkedHashMap<Long,String>();private var registered=false
 private val runnable=Runnable{scope.launch{query(false)}}
 private val observer=object:ContentObserver(handler){
  override fun onChange(selfChange:Boolean){schedule()}
  override fun onChange(selfChange:Boolean,uri:android.net.Uri?){schedule()}
 }
 fun register(){if(registered)return;registered=true;runCatching{resolver.registerContentObserver(MediaStore.Files.getContentUri("external"),true,observer)}.onFailure{Log.w(TAG,"Observer registration failed",it)};scope.launch{query(true)}}
 private fun schedule(){handler.removeCallbacks(runnable);handler.postDelayed(runnable,450L)}
 private fun query(initial:Boolean){
  val collection=MediaStore.Files.getContentUri("external")
  val columns=mutableListOf(BaseColumns._ID,MediaStore.MediaColumns.DISPLAY_NAME,MediaStore.MediaColumns.MIME_TYPE,MediaStore.MediaColumns.SIZE,MediaStore.MediaColumns.DATE_MODIFIED)
  if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.Q)columns+=MediaStore.MediaColumns.RELATIVE_PATH
  val selection="LOWER("+MediaStore.MediaColumns.DISPLAY_NAME+") LIKE ? OR LOWER("+MediaStore.MediaColumns.DISPLAY_NAME+") LIKE ?"
  val rows=LinkedHashMap<Long,DownloadCandidate>();val signatures=LinkedHashMap<Long,String>()
  try{resolver.query(collection,columns.toTypedArray(),selection,arrayOf("%.apk","%.exe"),null)?.use{cur->
   val id=cur.getColumnIndex(BaseColumns._ID);val name=cur.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME);val mime=cur.getColumnIndex(MediaStore.MediaColumns.MIME_TYPE);val size=cur.getColumnIndex(MediaStore.MediaColumns.SIZE);val mod=cur.getColumnIndex(MediaStore.MediaColumns.DATE_MODIFIED);val path=cur.getColumnIndex(MediaStore.MediaColumns.RELATIVE_PATH)
   if(id<0||name<0)return@use
   while(cur.moveToNext()){val rowId=cur.getLong(id);val n=cur.getString(name)?.take(180)?:continue;if(!n.endsWith(".apk",true)&&!n.endsWith(".exe",true))continue;val b=if(size>=0&&!cur.isNull(size))cur.getLong(size)else -1L;val m=if(mod>=0&&!cur.isNull(mod))cur.getLong(mod)else 0L;signatures[rowId]="$b:$m";rows[rowId]=DownloadCandidate(ContentUris.withAppendedId(collection,rowId),rowId,n,if(mime>=0)cur.getString(mime)else null,if(path>=0)cur.getString(path)else null,b,m)}
  }}catch(_:SecurityException){Log.w(TAG,"MediaStore access denied");return}catch(e:RuntimeException){Log.w(TAG,"MediaStore query failed",e);return}
  val dispatch=mutableListOf<DownloadCandidate>()
  synchronized(lock){if(initial){seen.clear();seen.putAll(signatures)}else{rows.forEach{(id,row)->if(seen[id]!=signatures[id])dispatch+=row;seen[id]=signatures[id].orEmpty()};seen.keys.filterNot(signatures::containsKey).forEach(seen::remove)};while(seen.size>1200){val it=seen.entries.iterator();if(it.hasNext()){it.next();it.remove()}else break}}
  dispatch.forEach{runCatching{onCandidate(it)}.onFailure{e->Log.w(TAG,"Candidate dispatch failed",e)}}
 }
 override fun close(){if(!registered)return;registered=false;handler.removeCallbacks(runnable);runCatching{resolver.unregisterContentObserver(observer)};synchronized(lock){seen.clear()};scope.cancel()}
 companion object{private const val TAG="SafeMobileMediaObserver"}
}
