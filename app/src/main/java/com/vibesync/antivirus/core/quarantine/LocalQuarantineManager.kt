package com.vibesync.antivirus.core.quarantine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.vibesync.antivirus.core.crypto.HashCalculator
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.UUID

data class QuarantineOutcome(val privateCopy: File, val originalRemoved: Boolean)

/** Copies only recognized on-device document-provider URIs to app-private no-backup storage. */
class LocalQuarantineManager(context: Context, private val hashCalculator: HashCalculator = HashCalculator()) {
 private val app = context.applicationContext

 fun supportsLocalUri(uri: Uri): Boolean = isKnownLocalUri(uri)

 fun quarantine(uri: Uri, expectedSha256: String?): QuarantineOutcome {
  require(isKnownLocalUri(uri)) { "For privacy, only recognized on-device storage providers are supported." }
  val resolver = app.contentResolver
  val name = File(uri.lastPathSegment.orEmpty()).name.take(80).ifBlank { "selected-file" }
  val folder = File(app.noBackupFilesDir, "quarantine")
  if (!folder.exists() && !folder.mkdirs()) throw IOException("Could not create private quarantine storage.")
  val root = app.noBackupFilesDir.canonicalFile
  val canonicalFolder = folder.canonicalFile
  require(canonicalFolder.path.startsWith(root.path + File.separator)) { "Invalid private quarantine location." }
  val destination = File(canonicalFolder, "${System.currentTimeMillis()}-${UUID.randomUUID()}-$name").canonicalFile
  require(destination.path.startsWith(canonicalFolder.path + File.separator)) { "Invalid quarantine filename." }
  val source = resolver.openInputStream(uri) ?: throw IOException("The selected local file could not be opened.")
  try {
   source.use { input ->
    FileOutputStream(destination).use { output ->
     val buffer = ByteArray(64 * 1024)
     var total = 0L
     val maxBytes = 512L * 1024L * 1024L
     while (true) {
      val count = input.read(buffer)
      if (count < 0) break
      if (count == 0) continue
      total += count
      require(total <= maxBytes) { "File exceeds the 512 MiB quarantine limit." }
      output.write(buffer, 0, count)
     }
     output.fd.sync()
    }
   }
   val copiedHash = hashCalculator.calculate(destination).sha256
   if (!expectedSha256.isNullOrBlank() && !copiedHash.equals(expectedSha256, ignoreCase = true)) {
    throw IOException("The file changed after scanning. Original was not removed.")
   }
   val removed = runCatching { resolver.delete(uri, null, null) > 0 }.getOrDefault(false)
   return QuarantineOutcome(destination, removed)
  } catch (error: Throwable) {
   if (destination.exists()) destination.delete()
   throw error
  }
 }

 /** Returns only regular files canonically contained directly in the private quarantine directory. */
 fun listQuarantinedFiles(): List<File> {
  val root = File(app.noBackupFilesDir, "quarantine").canonicalFile
  return root.listFiles().orEmpty()
   .filter { file ->
    runCatching {
     val canonical = file.canonicalFile
     canonical.isFile && canonical.parentFile == root
    }.getOrDefault(false)
   }
   .sortedByDescending { it.lastModified() }
 }

 /** Converts the opaque storage filename into the user-supplied filename when possible. */
 fun displayName(file: File): String {
  val safe = checkedQuarantineFile(file)
  return safe.name.replaceFirst(QUARANTINE_PREFIX, "").ifBlank { safe.name }
 }

 /**
  * Restores a copy selected by the user to a system document URI. The quarantined original
  * is deliberately retained; users can review it and delete it separately after restoration.
  */
 fun restoreToUri(file: File, destinationUri: Uri): Long {
  val source = checkedQuarantineFile(file)
  val expectedBytes = source.length()
  val bytesCopied = FileInputStream(source).use { input ->
   val output = app.contentResolver.openOutputStream(destinationUri, "wt")
    ?: throw IOException("Android could not open the chosen restore destination.")
   output.use { target -> input.copyTo(target, 64 * 1024) }
  }
  if (bytesCopied != expectedBytes) {
   throw IOException("Restored copy length did not match the quarantined file.")
  }
  return bytesCopied
 }

 fun deleteQuarantinedFile(file: File): Boolean {
  val safe = checkedQuarantineFile(file)
  return safe.delete()
 }

 private fun checkedQuarantineFile(file: File): File {
  val root = File(app.noBackupFilesDir, "quarantine").canonicalFile
  val safe = file.canonicalFile
  require(safe.path.startsWith(root.path + File.separator) && safe.isFile) {
   "Selected item is not a regular file inside SafeMobile quarantine."
  }
  require(safe.parentFile == root) { "Nested quarantine paths are not supported." }
  return safe
 }

 private fun isKnownLocalUri(uri: Uri): Boolean {
  if (!uri.scheme.equals("content", ignoreCase = true)) return false
  return when (uri.authority) {
   "com.android.externalstorage.documents" ->
    runCatching { DocumentsContract.isDocumentUri(app, uri) && DocumentsContract.getDocumentId(uri).isNotBlank() }.getOrDefault(false)
   "com.android.providers.downloads.documents" ->
    runCatching { DocumentsContract.isDocumentUri(app, uri) && !DocumentsContract.getDocumentId(uri).startsWith("all_downloads", true) }.getOrDefault(false)
   "com.android.providers.media.documents" ->
    runCatching { DocumentsContract.isDocumentUri(app, uri) }.getOrDefault(false)
   "com.android.providers.downloads" ->
    uri.path.orEmpty().startsWith("/public_downloads/") || uri.path.orEmpty().startsWith("/my_downloads/")
   "media" -> uri.path.orEmpty().startsWith("/external/")
   else -> false
  }
 }

 companion object {
  private val QUARANTINE_PREFIX = Regex("^\\d+-[0-9a-fA-F-]{36}-")
 }
}
