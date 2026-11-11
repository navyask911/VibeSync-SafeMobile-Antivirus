package com.vibesync.antivirus.core.hashdb

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.ZipInputStream

data class SignedHashDatabaseBundle(
    val databaseName: String,
    val databaseBytes: ByteArray,
    val detachedSignatureBytes: ByteArray,
    val archiveBytes: ByteArray
)

/** Reads a tiny, fixed-shape ZIP container with a detached signature; no path is extracted. */
object HashDatabaseBundleReader {
    private const val MAX_BUNDLE_BYTES = 18 * 1024 * 1024
    private const val MAX_SIGNATURE_BYTES = 4096

    fun read(input: InputStream): SignedHashDatabaseBundle {
        val archiveBytes = input.use { readBounded(it, MAX_BUNDLE_BYTES) }
        val entries = LinkedHashMap<String, ByteArray>()
        ZipInputStream(ByteArrayInputStream(archiveBytes)).use { zip ->
            var count = 0
            while (true) {
                val entry = zip.nextEntry ?: break
                count++
                require(count <= 2) { "Bundle must contain exactly one database and one detached signature." }
                require(!entry.isDirectory && isAllowedName(entry.name)) {
                    "Bundle contains an unexpected entry."
                }
                require(!entries.containsKey(entry.name)) { "Bundle contains duplicate entry names." }
                val limit = if (entry.name.endsWith(".sig", ignoreCase = true)) {
                    MAX_SIGNATURE_BYTES
                } else {
                    HashDatabaseFormat.MAX_DATABASE_BYTES
                }
                entries[entry.name] = readBounded(zip, limit)
                zip.closeEntry()
            }
        }
        require(entries.size == 2) { "Bundle is missing a database or detached signature." }
        val databaseNames = entries.keys.filterNot { it.endsWith(".sig", ignoreCase = true) }
        require(databaseNames.size == 1) { "Bundle must contain one database file." }
        val databaseName = databaseNames.single()
        val signature = entries[databaseName + ".sig"]
            ?: throw IllegalArgumentException("Detached signature file does not match the database name.")
        require(signature.isNotEmpty()) { "Detached signature is empty." }
        val database = entries[databaseName] ?: throw IllegalArgumentException("Database entry is missing.")
        require(database.isNotEmpty()) { "Database entry is empty." }
        return SignedHashDatabaseBundle(databaseName, database, signature, archiveBytes)
    }

    private fun isAllowedName(name: String): Boolean {
        if (name.contains('/') || name.contains('\\') || name == "." || name == "..") return false
        return name in setOf("hashes.sdb", "hashes.hdb", "hashes.hsb", "hashes.s1b") ||
            name in setOf("hashes.sdb.sig", "hashes.hdb.sig", "hashes.hsb.sig", "hashes.s1b.sig")
    }

    private fun readBounded(input: InputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(limit, 8192))
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            total += count
            require(total <= limit) { "Bundle entry exceeds its size limit." }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }
}
