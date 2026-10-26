package com.vibesync.antivirus.core.quarantine

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import com.google.crypto.tink.StreamingAead
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.streamingaead.StreamingAeadConfig
import com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates
import com.vibesync.antivirus.core.crypto.HashCalculator
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.Locale
import java.util.Properties
import java.util.UUID

data class QuarantineOutcome(val privateCopy: File, val originalRemoved: Boolean)

data class QuarantineMetadata(val originalName: String, val sha256: String, val originalBytes: Long, val recordId: String)

/**
 * Keeps quarantined content encrypted with Tink Streaming AEAD. The per-install Tink keyset is
 * wrapped with Android Keystore; if Keystore wrapping is unavailable, quarantine fails closed.
 * The original selected file is never deleted by this class.
 */
class LocalQuarantineManager(context: Context, private val hashCalculator: HashCalculator = HashCalculator()) {
 private val app = context.applicationContext
 private val maxQuarantineBytes = 512L * 1024L * 1024L

 fun supportsLocalUri(uri: Uri): Boolean = isKnownLocalUri(uri)

 fun isEncrypted(file: File): Boolean = file.extension.equals(ENCRYPTED_EXTENSION, ignoreCase = true)

 fun quarantine(uri: Uri, expectedSha256: String?, removeOriginalAfterVerified: Boolean = false): QuarantineOutcome {
  require(isKnownLocalUri(uri)) { "For privacy, only recognized on-device storage providers are supported." }
  val resolver = app.contentResolver
  val originalName = queryDisplayName(uri).ifBlank { "selected-file" }.let { File(it).name.take(120) }.ifBlank { "selected-file" }
  val folder = quarantineDirectory()
  val recordId = UUID.randomUUID().toString()
  val associatedData = recordId.toByteArray(Charsets.UTF_8)
  val temporaryCiphertext = File(folder, ".$recordId.$ENCRYPTED_EXTENSION.tmp")
  val ciphertext = File(folder, "${System.currentTimeMillis()}-$recordId.$ENCRYPTED_EXTENSION")
  val temporaryMetadata = File(folder, ".$recordId.meta.tmp")
  val metadataFile = metadataFile(ciphertext)
  val source = resolver.openInputStream(uri) ?: throw IOException("The selected local file could not be opened.")
  try {
   val sha = MessageDigest.getInstance("SHA-256")
   var total = 0L
   val primitive = streamingAead()
   source.use { input ->
    FileOutputStream(temporaryCiphertext).use { rawOutput ->
     val nonClosingOutput = object : FilterOutputStream(rawOutput) {
      override fun close() { flush() }
     }
     primitive.newEncryptingStream(nonClosingOutput, associatedData).use { encryptedOutput ->
      val buffer = ByteArray(HashCalculator.DEFAULT_BUFFER_SIZE)
      while (true) {
       val count = input.read(buffer)
       if (count < 0) break
       if (count == 0) continue
       total += count
       if (total > maxQuarantineBytes) throw IOException("File exceeds the 512 MiB quarantine limit.")
       sha.update(buffer, 0, count)
       encryptedOutput.write(buffer, 0, count)
      }
     }
     rawOutput.fd.sync()
    }
   }
   val copiedHash = sha.digest().toHex()
   if (!expectedSha256.isNullOrBlank() && !copiedHash.equals(expectedSha256, ignoreCase = true)) {
    throw IOException("The file changed after scanning. The original was retained.")
   }
   if (!temporaryCiphertext.renameTo(ciphertext)) throw IOException("Could not finalize the encrypted quarantine object.")
   verifyEncryptedObject(ciphertext, primitive, associatedData, copiedHash, total)
   val metadata = Properties().apply {
    setProperty("originalName", originalName)
    setProperty("sha256", copiedHash)
    setProperty("originalBytes", total.toString())
    setProperty("recordId", recordId)
    setProperty("createdAt", System.currentTimeMillis().toString())
   }
   FileOutputStream(temporaryMetadata).use { output ->
    metadata.store(output, "SafeMobile encrypted quarantine metadata")
    output.fd.sync()
   }
   if (!temporaryMetadata.renameTo(metadataFile)) throw IOException("Could not finalize quarantine metadata.")
   ciphertext.setExecutable(false, false)
   metadataFile.setExecutable(false, false)
   // The sentinel attempts source removal only after encrypted vault contents and metadata are verified and durable.
   val removed = removeOriginalAfterVerified && removeOriginal(uri)
   return QuarantineOutcome(ciphertext, originalRemoved = removed)
  } catch (error: Throwable) {
   temporaryCiphertext.delete()
   temporaryMetadata.delete()
   if (ciphertext.exists()) ciphertext.delete()
   if (metadataFile.exists() && !ciphertext.exists()) metadataFile.delete()
   throw error
  }
 }


 /** Encrypt and verify a direct file before attempting to remove the shared-storage source. */
 fun quarantineFile(file: File, expectedSha256: String?, removeOriginalAfterVerified: Boolean = true): QuarantineOutcome {
  val sourceFile = file.canonicalFile
  require(sourceFile.isFile && sourceFile.canRead()) { "The candidate file cannot be read." }
  val originalName = sourceFile.name.take(120).ifBlank { "selected-file" }
  val folder = quarantineDirectory()
  val recordId = UUID.randomUUID().toString()
  val associatedData = recordId.toByteArray(Charsets.UTF_8)
  val temporaryCiphertext = File(folder, ".$recordId.$ENCRYPTED_EXTENSION.tmp")
  val ciphertext = File(folder, "${System.currentTimeMillis()}-$recordId.$ENCRYPTED_EXTENSION")
  val temporaryMetadata = File(folder, ".$recordId.meta.tmp")
  val metaFile = metadataFile(ciphertext)
  try {
   var total = 0L
   val digest = MessageDigest.getInstance("SHA-256")
   val primitive = streamingAead()
   FileInputStream(sourceFile).use { input ->
    FileOutputStream(temporaryCiphertext).use { rawOutput ->
     val nonClosingOutput = object : FilterOutputStream(rawOutput) {
      override fun close() { flush() }
     }
     primitive.newEncryptingStream(nonClosingOutput, associatedData).use { encryptedOutput ->
      val buffer = ByteArray(HashCalculator.DEFAULT_BUFFER_SIZE)
      while (true) {
       val count = input.read(buffer)
       if (count < 0) break
       if (count == 0) continue
       total += count
       if (total > maxQuarantineBytes) throw IOException("File exceeds the 512 MiB quarantine limit.")
       digest.update(buffer, 0, count)
       encryptedOutput.write(buffer, 0, count)
      }
     }
     rawOutput.fd.sync()
    }
   }
   val copiedHash = digest.digest().toHex()
   if (!expectedSha256.isNullOrBlank() && !copiedHash.equals(expectedSha256, ignoreCase = true)) {
    throw IOException("The file changed after scanning. The original was retained.")
   }
   if (!temporaryCiphertext.renameTo(ciphertext)) throw IOException("Could not finalize the encrypted quarantine object.")
   verifyEncryptedObject(ciphertext, primitive, associatedData, copiedHash, total)
   val metadata = Properties().apply {
    setProperty("originalName", originalName)
    setProperty("sha256", copiedHash)
    setProperty("originalBytes", total.toString())
    setProperty("recordId", recordId)
    setProperty("createdAt", System.currentTimeMillis().toString())
   }
   FileOutputStream(temporaryMetadata).use { output ->
    metadata.store(output, "SafeMobile encrypted quarantine metadata")
    output.fd.sync()
   }
   if (!temporaryMetadata.renameTo(metaFile)) throw IOException("Could not finalize quarantine metadata.")
   ciphertext.setExecutable(false, false)
   metaFile.setExecutable(false, false)
   val removed = removeOriginalAfterVerified && runCatching { sourceFile.delete() }.getOrDefault(false)
   return QuarantineOutcome(ciphertext, originalRemoved = removed)
  } catch (error: Throwable) {
   temporaryCiphertext.delete()
   temporaryMetadata.delete()
   if (ciphertext.exists() && !metaFile.exists()) ciphertext.delete()
   throw error
  }
 }

 /** Retry original deletion only after the caller already saved a verified encrypted vault copy. */
 fun retryRemoveOriginal(uri: Uri): Boolean = removeOriginal(uri)
 fun retryRemoveOriginal(file: File): Boolean =
  runCatching { file.canonicalFile.takeIf { it.isFile }?.delete() == true }.getOrDefault(false)

 private fun removeOriginal(uri: Uri): Boolean {
  if (!supportsLocalUri(uri)) return false
  val resolver = app.contentResolver
  return runCatching {
   if (DocumentsContract.isDocumentUri(app, uri)) {
    runCatching { DocumentsContract.deleteDocument(resolver, uri) }.getOrElse {
     resolver.delete(uri, null, null) > 0
    }
   } else {
    resolver.delete(uri, null, null) > 0
   }
  }.getOrDefault(false)
 }

  /** Lists encrypted records and old pre-hardening plaintext records without hiding user data. */
 fun listQuarantinedFiles(): List<File> {
  val root = quarantineDirectory().canonicalFile
  return root.listFiles().orEmpty()
   .filter { file ->
    runCatching {
     val canonical = file.canonicalFile
     canonical.isFile && canonical.parentFile == root &&
      !canonical.name.endsWith(".meta", true) &&
      !canonical.name.endsWith(".tmp", true) &&
      !canonical.name.startsWith(".")
    }.getOrDefault(false)
   }
   .sortedByDescending { it.lastModified() }
 }

 fun displayName(file: File): String {
  val safe = checkedQuarantineFile(file)
  if (!isEncrypted(safe)) {
   return safe.name.replaceFirst(LEGACY_PREFIX, "").ifBlank { "Legacy quarantined file" }
  }
  return runCatching { readMetadata(safe).originalName }.getOrDefault("Encrypted quarantined file")
 }

 fun displaySize(file: File): Long {
  val safe = checkedQuarantineFile(file)
  return if (isEncrypted(safe)) runCatching { readMetadata(safe).originalBytes }.getOrDefault(0L) else safe.length()
 }

 /**
  * Decrypts to a short-lived app-private cache file first, ensuring Streaming AEAD has verified
  * the ciphertext before any plaintext is written to the user-chosen destination.
  */
 fun restoreToUri(file: File, destinationUri: Uri): Long {
  val source = checkedQuarantineFile(file)
  val temporaryPlaintext = File.createTempFile("safemobile-restore-", ".tmp", app.cacheDir)
  try {
   val expectedMetadata = if (isEncrypted(source)) readMetadata(source) else null
   val expectedHash = expectedMetadata?.sha256 ?: hashCalculator.calculate(source).sha256
   if (isEncrypted(source)) {
    val id = expectedMetadata?.recordId ?: recordIdFromFile(source)
    FileInputStream(source).use { encryptedInput ->
     streamingAead().newDecryptingStream(encryptedInput, id.toByteArray(Charsets.UTF_8)).use { plaintextInput ->
      FileOutputStream(temporaryPlaintext).use { output ->
       plaintextInput.copyTo(output, HashCalculator.DEFAULT_BUFFER_SIZE)
       output.fd.sync()
      }
     }
    }
   } else {
    // Legacy plaintext quarantine entries remain restorable, but are not represented as encrypted.
    FileInputStream(source).use { input ->
     FileOutputStream(temporaryPlaintext).use { output ->
      input.copyTo(output, HashCalculator.DEFAULT_BUFFER_SIZE)
      output.fd.sync()
     }
    }
   }
   val restoredHash = hashCalculator.calculate(temporaryPlaintext).sha256
   if (!restoredHash.equals(expectedHash, ignoreCase = true)) {
    throw IOException("Authenticated restore hash verification failed.")
   }
   val expectedBytes = expectedMetadata?.originalBytes ?: source.length()
   if (temporaryPlaintext.length() != expectedBytes) throw IOException("Restored content length did not match quarantine metadata.")
   val output = app.contentResolver.openOutputStream(destinationUri, "wt")
    ?: throw IOException("Android could not open the chosen restore destination.")
   val bytesCopied = FileInputStream(temporaryPlaintext).use { input ->
    output.use { target -> input.copyTo(target, HashCalculator.DEFAULT_BUFFER_SIZE) }
   }
   if (bytesCopied != expectedBytes) throw IOException("Restored copy length did not match quarantine metadata.")
   val verifyInput = app.contentResolver.openInputStream(destinationUri)
    ?: throw IOException("The destination could not be reopened for integrity verification; the quarantined copy was retained.")
   val verified = verifyInput.use { hashCalculator.calculate(it).sha256 }
   if (!verified.equals(expectedHash, ignoreCase = true)) {
    throw IOException("Destination hash verification failed; the quarantined copy was retained.")
   }
   return bytesCopied
  } finally {
   temporaryPlaintext.delete()
  }
 }

 fun deleteQuarantinedFile(file: File): Boolean {
  // Validate the canonical vault path before accessing or removing the encrypted payload.
  // Android permissions/storage can change between showing the vault and confirmation.
  val safe = try {
   checkedQuarantineFile(file)
  } catch (_: SecurityException) {
   return false
  } catch (_: java.io.FileNotFoundException) {
   return false
  } catch (_: Exception) {
   return false
  }
  if (!QuarantineFileDeletion.delete(safe)) return false
  // Only after deleting the encrypted payload may its metadata sidecar be removed.
  runCatching {
   val sidecar = metadataFile(safe)
   if (sidecar.exists()) sidecar.delete()
  }
  return true
 }

 private fun verifyEncryptedObject(
  ciphertext: File,
  primitive: StreamingAead,
  associatedData: ByteArray,
  expectedHash: String,
  expectedBytes: Long
 ) {
  val digest = MessageDigest.getInstance("SHA-256")
  var total = 0L
  FileInputStream(ciphertext).use { encryptedInput ->
   primitive.newDecryptingStream(encryptedInput, associatedData).use { plaintextInput ->
    val buffer = ByteArray(HashCalculator.DEFAULT_BUFFER_SIZE)
    while (true) {
     val count = plaintextInput.read(buffer)
     if (count < 0) break
     if (count == 0) continue
     total += count
     if (total > maxQuarantineBytes) throw IOException("Decrypted quarantine object exceeded the permitted size.")
     digest.update(buffer, 0, count)
    }
   }
  }
  if (total != expectedBytes || !digest.digest().toHex().equals(expectedHash, ignoreCase = true)) {
   throw IOException("Encrypted quarantine verification failed.")
  }
 }

 private fun streamingAead(): StreamingAead {
  StreamingAeadConfig.register()
  val manager = AndroidKeysetManager.Builder()
   .withSharedPref(app, KEYSET_NAME, KEYSET_PREFS)
   .withKeyTemplate(StreamingAeadKeyTemplates.AES256_GCM_HKDF_4KB)
   .withMasterKeyUri(MASTER_KEY_URI)
   .build()
  if (!manager.isUsingKeystore) {
   throw GeneralSecurityException("Android Keystore wrapping is unavailable; refusing unencrypted quarantine.")
  }
  return manager.keysetHandle.getPrimitive(StreamingAead::class.java)
 }

 private fun quarantineDirectory(): File {
  val folder = File(app.noBackupFilesDir, "quarantine")
  if (!folder.exists() && !folder.mkdirs()) throw IOException("Could not create private quarantine storage.")
  val root = app.noBackupFilesDir.canonicalFile
  val canonical = folder.canonicalFile
  require(canonical.path.startsWith(root.path + File.separator)) { "Invalid private quarantine location." }
  return canonical
 }

 private fun queryDisplayName(uri: Uri): String {
  return runCatching {
   app.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
    if (cursor.moveToFirst()) cursor.getString(0).orEmpty() else ""
   }.orEmpty()
  }.getOrDefault("")
 }

 private fun readMetadata(file: File): QuarantineMetadata {
  val metaFile = metadataFile(file)
  if (!metaFile.isFile) throw IOException("Quarantine metadata is missing.")
  val props = Properties()
  FileInputStream(metaFile).use { props.load(it) }
  val hash = props.getProperty("sha256").orEmpty()
  val name = props.getProperty("originalName").orEmpty()
  val bytes = props.getProperty("originalBytes")?.toLongOrNull()
   ?: throw IOException("Quarantine size metadata is invalid.")
  val recordId = props.getProperty("recordId").orEmpty()
  require(hash.matches(Regex("^[0-9a-fA-F]{64}$")) && name.isNotBlank() && bytes >= 0L) {
   "Quarantine metadata failed validation."
  }
  require(recordId == recordIdFromFile(file)) { "Quarantine identifier does not match its metadata." }
  return QuarantineMetadata(name, hash.lowercase(Locale.ROOT), bytes, recordId)
 }

 private fun metadataFile(file: File): File =
  File(file.parentFile, file.name.removeSuffix(".$ENCRYPTED_EXTENSION") + ".meta")

 private fun recordIdFromFile(file: File): String {
  val stem = file.name.removeSuffix(".$ENCRYPTED_EXTENSION")
  val id = stem.substringAfter("-", "")
  require(id.matches(Regex("^[0-9a-fA-F-]{36}$"))) { "Invalid quarantine record ID." }
  return id
 }

 private fun checkedQuarantineFile(file: File): File {
  val root = quarantineDirectory().canonicalFile
  val safe = file.canonicalFile
  require(safe.path.startsWith(root.path + File.separator) && safe.isFile && safe.parentFile == root) {
   "Selected item is not a regular file inside SafeMobile quarantine."
  }
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

 private fun ByteArray.toHex(): String =
  joinToString("") { String.format(Locale.ROOT, "%02x", it.toInt() and 0xff) }

 companion object {
  private const val ENCRYPTED_EXTENSION = "smq"
  private const val KEYSET_NAME = "safemobile_quarantine_keyset"
  private const val KEYSET_PREFS = "safemobile_quarantine_crypto"
  private const val MASTER_KEY_URI = "android-keystore://safemobile_quarantine_master"
  private val LEGACY_PREFIX = Regex("^\\d+-[0-9a-fA-F-]{36}-")
 }
}

