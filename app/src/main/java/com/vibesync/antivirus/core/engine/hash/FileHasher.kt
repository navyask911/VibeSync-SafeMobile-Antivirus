package com.vibesync.antivirus.core.engine.hash

import java.io.File
import java.security.MessageDigest
import java.util.Locale

/**
 * Calculates MD5 and SHA-256 while reading the file exactly once.
 */
class FileHasher {

    companion object {
        private const val BUFFER_SIZE = 8192

        @JvmStatic
        fun calculateHashes(file: File): Pair<String, String> {
            require(file.isFile && file.canRead()) { "File is not readable: ${file.name}" }

            val md5 = MessageDigest.getInstance("MD5")
            val sha256 = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(BUFFER_SIZE)

            file.inputStream().use { input ->
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    md5.update(buffer, 0, count)
                    sha256.update(buffer, 0, count)
                }
            }

            return md5.digest().toHex() to sha256.digest().toHex()
        }

        private fun ByteArray.toHex(): String =
            joinToString("") { byte ->
                String.format(Locale.ROOT, "%02x", byte.toInt() and 0xff)
            }
    }
}
