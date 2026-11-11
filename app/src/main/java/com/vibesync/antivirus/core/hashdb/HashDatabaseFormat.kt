package com.vibesync.antivirus.core.hashdb

import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Locale

enum class HashAlgorithm(val token: String, val length: Int) {
    MD5("md5", 32),
    SHA1("sha1", 40),
    SHA256("sha256", 64);

    companion object {
        fun fromToken(value: String): HashAlgorithm? =
            entries.firstOrNull { it.token.equals(value, ignoreCase = true) }

        fun fromDatabaseName(name: String): HashAlgorithm? = when {
            name.endsWith(".hdb", ignoreCase = true) -> MD5
            name.endsWith(".hsb", ignoreCase = true) -> SHA256
            name.endsWith(".s1b", ignoreCase = true) -> SHA1
            name.endsWith(".sdb", ignoreCase = true) -> null
            else -> null
        }
    }
}

data class HashDatabaseRecord(
    val algorithm: HashAlgorithm,
    val hash: String,
    val threatName: String,
    val fileSize: Long? = null
) {
    val bloomKey: String get() = algorithm.token + ":" + hash
}

data class ParsedHashDatabase(
    val version: Long,
    val source: String,
    val license: String,
    val records: List<HashDatabaseRecord>
)

/**
 * Parses signed SafeMobile hash bundles and a bounded subset of ClamAV-style .hdb/.hsb records.
 *
 * Header, signature, source, and license metadata are part of the signed bytes:
 * # SAFEHASH version=42 source=publisher-id license=CC0-1.0
 *
 * A multi-algorithm .sdb uses "md5:HASH:name", "sha1:HASH:name" or
 * "sha256:HASH:name". ClamAV records use "HASH:size:name"; the file extension
 * selects MD5 (.hdb), SHA-256 (.hsb), or SHA-1 (.s1b).
 */
object HashDatabaseFormat {
    const val MAX_DATABASE_BYTES = 16 * 1024 * 1024
    const val MAX_RECORDS = 200_000
    private const val MAX_LINE_LENGTH = 4096
    private const val MAX_NAME_LENGTH = 200
    private val HEADER = Regex("^# SAFEHASH version=(\\d+) source=([A-Za-z0-9._/-]{1,120}) license=([A-Za-z0-9.+-]{1,80})$")
    private val HEX = Regex("^[a-fA-F0-9]+$")

    fun parse(bytes: ByteArray, defaultAlgorithm: HashAlgorithm? = null): ParsedHashDatabase {
        require(bytes.isNotEmpty() && bytes.size <= MAX_DATABASE_BYTES) {
            "Database is empty or exceeds the byte limit."
        }
        val decoder = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val reader = BufferedReader(InputStreamReader(ByteArrayInputStream(bytes), decoder))
        reader.use { input ->
            val headerLine = input.readLine() ?: throw IllegalArgumentException("Missing database header.")
            val header = HEADER.matchEntire(headerLine.trimEnd('\r'))
                ?: throw IllegalArgumentException("Invalid signed database header.")
            val version = header.groupValues[1].toLongOrNull()
                ?: throw IllegalArgumentException("Invalid database version.")
            require(version > 0L) { "Database version must be positive." }
            val source = header.groupValues[2]
            val license = header.groupValues[3]
            val records = ArrayList<HashDatabaseRecord>()
            val seen = HashSet<String>()
            var lineNumber = 1
            while (true) {
                val raw = input.readLine() ?: break
                lineNumber++
                require(raw.length <= MAX_LINE_LENGTH) { "Database line exceeds the size limit." }
                val line = raw.trim()
                if (line.isEmpty() || line.startsWith("#")) continue
                require(line.none { Character.isISOControl(it) }) { "Invalid control character at line " + lineNumber + "." }
                val record = parseRecord(line, defaultAlgorithm, lineNumber)
                require(seen.add(record.bloomKey)) { "Duplicate hash at line " + lineNumber + "." }
                records += record
                require(records.size <= MAX_RECORDS) { "Database contains too many records." }
            }
            require(records.isNotEmpty()) { "Database contains no valid signature records." }
            return ParsedHashDatabase(version, source, license, records)
        }
    }

    private fun parseRecord(line: String, defaultAlgorithm: HashAlgorithm?, lineNumber: Int): HashDatabaseRecord {
        val parts = line.split(':', limit = 3)
        require(parts.isNotEmpty()) { "Empty record at line " + lineNumber + "." }
        val explicitAlgorithm = HashAlgorithm.fromToken(parts[0])
        val algorithm: HashAlgorithm
        val digest: String
        var name = ""
        var size: Long? = null

        if (explicitAlgorithm != null) {
            require(parts.size >= 2) { "Missing hash at line " + lineNumber + "." }
            algorithm = explicitAlgorithm
            digest = parts[1].trim()
            name = parts.getOrNull(2).orEmpty().trim()
        } else {
            algorithm = defaultAlgorithm
                ?: throw IllegalArgumentException("An algorithm prefix is required at line " + lineNumber + ".")
            digest = parts[0].trim()
            if (parts.size == 3 && parts[1].trim().matches(Regex("^\\d+$"))) {
                size = parts[1].trim().toLongOrNull()
                    ?: throw IllegalArgumentException("Invalid file size at line " + lineNumber + ".")
                name = parts[2].trim()
            } else if (parts.size >= 2) {
                name = if (parts.size == 2) parts[1].trim() else (parts[1] + ":" + parts[2]).trim()
            }
        }

        if (defaultAlgorithm != null) require(algorithm == defaultAlgorithm) { "Hash algorithm does not match the .hdb/.hsb database file type at line " + lineNumber + "." }
        require(digest.length == algorithm.length && HEX.matches(digest)) {
            "Invalid " + algorithm.token.uppercase(Locale.ROOT) + " hash at line " + lineNumber + "."
        }
        require(size == null || size >= 0L) { "Invalid file size at line " + lineNumber + "." }
        require(name.length <= MAX_NAME_LENGTH && name.none { Character.isISOControl(it) }) {
            "Invalid threat label at line " + lineNumber + "."
        }
        val safeName = name.ifBlank { algorithm.token.uppercase(Locale.ROOT) + " signature" }
        return HashDatabaseRecord(algorithm, digest.lowercase(Locale.ROOT), safeName, size)
    }
}
