package com.vibesync.antivirus.core.crypto
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

/** Streaming SHA-256 and MD5; each call owns independent digests and bounded buffer. */
class HashCalculator(private val bufferSize: Int = DEFAULT_BUFFER_SIZE) {
 init { require(bufferSize in 4096..1048576) { "Buffer size must be 4 KiB to 1 MiB" } }
 data class HashResult(val sha256: String, val md5: String, val bytesRead: Long)
 fun calculate(file: File): HashResult = file.inputStream().buffered(bufferSize).use { calculate(it) }
 fun calculate(input: InputStream): HashResult {
  val sha = MessageDigest.getInstance("SHA-256")
  val md5 = MessageDigest.getInstance("MD5")
  val buffer = ByteArray(bufferSize)
  var total = 0L
  while (true) {
   val count = input.read(buffer)
   if (count < 0) break
   if (count == 0) continue
   sha.update(buffer, 0, count)
   md5.update(buffer, 0, count)
   total += count
  }
  return HashResult(sha.digest().toHex(), md5.digest().toHex(), total)
 }
 private fun ByteArray.toHex(): String = joinToString("") { String.format(Locale.ROOT, "%02x", it.toInt() and 255) }
 companion object { const val DEFAULT_BUFFER_SIZE = 65536 }
}
