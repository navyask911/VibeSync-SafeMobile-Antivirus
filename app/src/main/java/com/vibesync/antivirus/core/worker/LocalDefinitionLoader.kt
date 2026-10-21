package com.vibesync.antivirus.core.worker

import android.content.Context
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.data.local.ThreatDao
import com.vibesync.antivirus.data.local.ThreatSignature
import kotlinx.coroutines.sync.Mutex
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

/**
 * Imports user-selected local JSON definitions.
 *
 * This validates structure and fields but does not authenticate the publisher. The UI must
 * disclose that limitation. No remote threat feed is trusted or enabled by this loader.
 */
class LocalDefinitionLoader(
    private val context: Context,
    private val dao: ThreatDao,
    private val hashStore: EncryptedHashStore
) {
    private val importMutex = Mutex()

    suspend fun importBundledIfEmpty(): Int {
        importMutex.lock()
        try {
            if (dao.countSignatures() > 0) return 0
            val stream = try {
                context.assets.open("offline-threat-definitions.json")
            } catch (_: IOException) {
                return 0
            }
            return parseAndImport(stream)
        } finally {
            importMutex.unlock()
        }
    }

    /**
     * Expected format:
     * {"schema_version":1,"definitions":[{"sha256":"64 hex chars",
     * "malware_family":"label","threat_level":"test|low|medium|high|critical|unknown",
     * "date_added":1234567890000}]}
     *
     * The user chooses this file explicitly. Schema validation is not cryptographic provenance.
     */
    suspend fun importFromStream(stream: InputStream): Int {
        importMutex.lock()
        try {
            return parseAndImport(stream)
        } finally {
            importMutex.unlock()
        }
    }

    private suspend fun parseAndImport(stream: InputStream): Int {
        val payload = stream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                total += count
                require(total <= MAX_IMPORT_BYTES) { "Definition file exceeds the supported size limit." }
                output.write(buffer, 0, count)
            }
            output.toString(Charsets.UTF_8.name())
        }

        val root = JSONObject(payload)
        require(root.optInt("schema_version", -1) == SUPPORTED_SCHEMA_VERSION) {
            "Unsupported or missing definition schema version."
        }
        val definitions = root.optJSONArray("definitions")
            ?: throw IllegalArgumentException("Expected a definitions array.")
        require(definitions.length() in 1..MAX_DEFINITIONS) {
            "Definition count is empty or exceeds the supported limit."
        }

        val rows = ArrayList<ThreatSignature>(definitions.length())
        val seenHashes = HashSet<String>(definitions.length())
        for (index in 0 until definitions.length()) {
            val row = definitions.optJSONObject(index)
                ?: throw IllegalArgumentException("Definition $index is not a JSON object.")
            val hash = row.optString("sha256", "").lowercase()
            require(hash.matches(SHA256_PATTERN)) { "Definition $index has an invalid SHA-256 value." }
            require(seenHashes.add(hash)) { "Duplicate SHA-256 definition at index $index." }

            val family = row.optString("malware_family", "").trim()
            require(family.isNotEmpty() && family.length <= MAX_FAMILY_LENGTH && family.none { Character.isISOControl(it) }) {
                "Definition $index has an invalid malware_family label."
            }
            val level = row.optString("threat_level", "").trim().lowercase()
            require(level in ALLOWED_THREAT_LEVELS) { "Definition $index has an unsupported threat_level." }
            val dateAdded = row.optLong("date_added", -1L)
            require(dateAdded > 0L) { "Definition $index has an invalid date_added timestamp." }

            rows += ThreatSignature(
                hash = hashStore.protectHash(hash),
                malwareFamily = hashStore.protectMetadata(family, "family"),
                threatLevel = hashStore.protectMetadata(level, "level"),
                dateAdded = dateAdded
            )
        }

        // Validate the whole file before writing any rows. Room's generated @Insert(list)
        // implementation runs as one transaction, preventing a silently partial import.
        dao.upsertSignatures(rows)
        return rows.size
    }

    companion object {
        private const val SUPPORTED_SCHEMA_VERSION = 1
        private const val MAX_IMPORT_BYTES = 8 * 1024 * 1024
        private const val MAX_DEFINITIONS = 50_000
        private const val MAX_FAMILY_LENGTH = 120
        private val SHA256_PATTERN = Regex("^[a-f0-9]{64}$")
        private val ALLOWED_THREAT_LEVELS = setOf("test", "low", "medium", "high", "critical", "unknown")
    }
}
