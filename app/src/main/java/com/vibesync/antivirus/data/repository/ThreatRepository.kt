package com.vibesync.antivirus.data.repository
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.local.ThreatDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

class ThreatRepository(private val context: Context, private val database: ThreatDatabase, private val scanner: PackageScanner) {
 suspend fun scanInstalledApps(): List<ScanResult> = withContext(Dispatchers.IO) { scanner.scanInstalledApps() }
 suspend fun scanInstalledPackage(name: String): ScanResult? = withContext(Dispatchers.IO) { scanner.scanInstalledPackage(name) }
 suspend fun scanFile(file: File): ScanResult = withContext(Dispatchers.IO) { scanner.scanFile(file) }
 suspend fun scanUri(uri: Uri): ScanResult = withContext(Dispatchers.IO) {
  val label = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
   if (cursor.moveToFirst()) cursor.getString(0) else null
  } ?: uri.lastPathSegment ?: "selected-file"
  val stream = context.contentResolver.openInputStream(uri)
   ?: return@withContext ScanResult(label, label, null, null, ScanVerdict.NOT_SCANNED, listOf(context.getString(R.string.file_stream_failed)), 0)
  scanner.scanStream(label, stream)
 }
 suspend fun signatureCount(): Int = withContext(Dispatchers.IO) { database.threatDao().countSignatures() }
 suspend fun deepScan(): List<ScanResult> = withContext(Dispatchers.IO) {
  val results = scanner.scanInstalledApps()
  if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R && android.os.Environment.isExternalStorageManager()) {
   val downloads = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
   if (downloads.isDirectory) downloads.walkTopDown().maxDepth(3).filter { it.isFile && it.extension.equals("apk", true) }.take(100).forEach { scanner.scanFile(it) }
  }
  results
 }
}
