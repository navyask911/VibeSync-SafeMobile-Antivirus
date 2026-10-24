package com.vibesync.antivirus.core.worker

import com.vibesync.antivirus.data.local.MalwareHashEntity
import java.io.InputStream
import java.util.Locale

/**
 * File-hash-only importer, not a ClamAV runtime.
 * .hdb = MD5:size:name, .hsb = SHA1/SHA256:size:name.
 * .sdb is SafeMobile-defined: algorithm:hex:size:name.
 *
 * Wildcard file sizes and ClamAV extension fields are rejected, never silently ignored.
 * The importer is invoked only after detached-bundle signature verification.
 */
internal class SignedHashFormatParser(private val batchSize: Int = 500) {
    init { require(batchSize in 1..1_000) }

    suspend fun parse(
        input: InputStream,
        format: String,
        source: String,
        onBatch: suspend (List<MalwareHashEntity>) -> Unit
    ): Int {
        require(format in setOf("hdb", "hsb", "sdb")) { "Unsupported hash database format." }
        val batch = ArrayList<MalwareHashEntity>(batchSize)
        var rows = 0
        input.bufferedReader(Charsets.UTF_8).use { reader ->
            while (true) {
                val line = reader.readLine() ?: break
                require(line.length <= MAX_LINE_CHARS) { "Hash signature line exceeds size limit." }
                if (line.isBlank() || line.startsWith("#")) continue
                require(++rows <= MAX_RECORDS) { "Too many hash signatures in this import." }
                val fields = line.split(':')
                val algorithm: String
                val hash: String
                val size: String
                val family: String
                if (format == "sdb") {
                    require(fields.size == 4) { "Malformed sdb record." }
                    algorithm = fields[0].lowercase(Locale.ROOT)
                    hash = fields[1].lowercase(Locale.ROOT)
                    size = fields[2]
                    family = fields[3]
                } else {
                    require(fields.size == 3) { "Malformed ClamAV hash record." }
                    algorithm = when (fields[0].length) {
                        32 -> "md5"
                        40 -> "sha1"
                        64 -> "sha256"
                        else -> throw IllegalArgumentException("Unsupported digest length.")
                    }
                    hash = fields[0].lowercase(Locale.ROOT)
                    size = fields[1]
                    family = fields[2]
                }
                require(algorithm in setOf("md5", "sha1", "sha256")) { "Unsupported hash algorithm." }
                require(format != "hdb" || algorithm == "md5") { "hdb requires MD5 digests." }
                require(format != "hsb" || algorithm != "md5") { "hsb requires SHA1 or SHA256 digests." }
                val expectedLength = when (algorithm) { "md5" -> 32; "sha1" -> 40; else -> 64 }
                require(hash.length == expectedLength && hash.all { it in '0'..'9' || it in 'a'..'f' }) {
                    "Invalid digest."
                }
                require(size.isNotEmpty() && size.all(Char::isDigit)) {
                    "Exact file size required; wildcard sizes are not supported."
                }
                val length = size.toLongOrNull()
                require(length != null && length >= 0L) { "Invalid file size." }
                require(family.length in 1..120 && family.all {
                    it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' || it == '.'
                }) { "Unsupported signature label." }

                batch += MalwareHashEntity(
                    indicatorKey = source + ":" + algorithm + ":" + hash + ":" + length,
                    md5Hash = hash.takeIf { algorithm == "md5" },
                    sha1Hash = hash.takeIf { algorithm == "sha1" },
                    sha256Hash = hash.takeIf { algorithm == "sha256" },
                    fileSize = length,
                    threatName = family,
                    source = source
                )
                if (batch.size >= batchSize) {
                    onBatch(batch.toList())
                    batch.clear()
                }
            }
        }
        require(rows > 0) { "Empty hash signature database." }
        if (batch.isNotEmpty()) onBatch(batch.toList())
        return rows
    }

    companion object {
        private const val MAX_LINE_CHARS = 1024
        private const val MAX_RECORDS = 100_000
    }
}
