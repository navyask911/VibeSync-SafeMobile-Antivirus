package com.vibesync.antivirus.data.repository
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.worker.LocalDefinitionLoader
import com.vibesync.antivirus.data.local.ThreatDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

class ThreatRepository(private val context: Context, private val database: ThreatDatabase, private val scanner: PackageScanner, private val definitionLoader: LocalDefinitionLoader) {
 suspend fun scanInstalledApps(): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanInstalledApps()
 }
 suspend fun scanInstalledPackage(name: String): ScanResult? = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanInstalledPackage(name)
 }
 suspend fun scanFile(file: File): ScanResult = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  scanner.scanFile(file)
 }
 suspend fun scanUri(uri: Uri): ScanResult = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  val label=context.contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),null,null,null)?.use { c -> if(c.moveToFirst()) c.getString(0) else null } ?: uri.lastPathSegment ?: context.getString(R.string.unknown_file)
  val stream=context.contentResolver.openInputStream(uri) ?: return@withContext ScanResult(label,label,null,null,ScanVerdict.NOT_SCANNED,listOf(context.getString(R.string.file_stream_failed)),0)
  scanner.scanStream(label,stream)
 }
 suspend fun importOfflineDefinitions(uri: Uri): String = withContext(Dispatchers.IO) {
  val stream=context.contentResolver.openInputStream(uri) ?: throw IOException(context.getString(R.string.file_stream_failed))
  context.getString(R.string.import_success,definitionLoader.importFromStream(stream))
 }
 suspend fun signatureCount(): Int = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  database.threatDao().countSignatures()
 }
 suspend fun deepScan(): List<ScanResult> = withContext(Dispatchers.IO) {
  definitionLoader.importBundledIfEmpty()
  val results=scanner.scanInstalledApps()
  if(android.os.Build.VERSION.SDK_INT>=android.os.Build.VERSION_CODES.R && android.os.Environment.isExternalStorageManager()) {
   val downloads=android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
   if(downloads.isDirectory) downloads.walkTopDown().maxDepth(3).filter { it.isFile && it.extension.equals("apk",true) }.take(100).forEach { scanner.scanFile(it) }
  }
  results
 }
}
