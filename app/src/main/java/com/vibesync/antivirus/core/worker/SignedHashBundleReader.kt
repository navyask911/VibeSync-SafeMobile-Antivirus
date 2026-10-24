package com.vibesync.antivirus.core.worker

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipInputStream

/**
 * A strictly bounded SAF archive with exactly three entries:
 * manifest.json, manifest.sig (64 raw detached Ed25519 bytes), hashes.(hdb|hsb|sdb).
 *
 * The entire manifest is signed and its exact payload SHA-256 is checked before import.
 * Archives are never extracted to disk and no network access is performed.
 */
internal object SignedHashBundleReader {
    data class VerifiedBundle(
        val manifest: VerifiedFeedManifest,
        val format: String,
        val payload: ByteArray
    )

    fun read(input: InputStream, publicKeyBase64: String): VerifiedBundle {
        require(publicKeyBase64.isNotBlank()) { "No trusted definition signing key is configured; manual import is disabled." }
        val parts = HashMap<String, ByteArray>(3)
        ZipInputStream(LimitedInputStream(input, MAX_ZIP_BYTES)).use { archive ->
            while (true) {
                val entry = archive.nextEntry ?: break
                require(!entry.isDirectory && entry.name in ALLOWED_NAMES) { "Archive contains an unexpected entry." }
                require(!parts.containsKey(entry.name)) { "Archive contains duplicate entries." }
                val limit = when (entry.name) {
                    "manifest.json" -> MAX_MANIFEST_BYTES
                    "manifest.sig" -> 64
                    else -> MAX_PAYLOAD_BYTES
                }
                val output = ByteArrayOutputStream(minOf(limit, 8192))
                val buffer = ByteArray(8192)
                while (true) {
                    val count = archive.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= limit) { "Signed bundle entry exceeds its size limit." }
                    output.write(buffer, 0, count)
                }
                parts[entry.name] = output.toByteArray()
                require(parts.size <= 3) { "Archive has more entries than expected." }
                archive.closeEntry()
            }
        }

        val manifestBytes = parts["manifest.json"] ?: error("Unsigned bundle: manifest missing.")
        val signature = parts["manifest.sig"] ?: error("Unsigned bundle: signature missing.")
        require(manifestBytes.isNotEmpty() && signature.size == 64) { "Invalid signed manifest or signature." }
        val format = JSONObject(String(manifestBytes, StandardCharsets.UTF_8)).optString("format", "")
        require(format in setOf("hdb", "hsb", "sdb")) { "Manifest format is missing or unsupported." }
        val fileName = "hashes." + format
        val payload = parts[fileName] ?: error("Signed bundle payload is missing or mismatched.")
        require(parts.size == 3 && payload.isNotEmpty()) { "Signed bundle must contain exactly the expected entries." }
        val verified = SignedFeedManifestVerifier.verifyHeaders(
            Base64.getEncoder().encodeToString(manifestBytes),
            Base64.getEncoder().encodeToString(signature),
            publicKeyBase64
        )
        // The source ID is signed, and is namespaced by the importer before persistence.
        SignedFeedManifestVerifier.validateSourceAndVersion(verified, verified.sourceKey, 0L)
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
            .joinToString("") { "%02x".format(it) }
        SignedFeedManifestVerifier.validatePayload(verified, digest)
        return VerifiedBundle(verified, format, payload)
    }

    private class LimitedInputStream(input: InputStream, private val max: Long) : FilterInputStream(input) {
        private var seen = 0L
        override fun read(): Int {
            val b = super.read()
            if (b >= 0) add(1)
            return b
        }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val n = super.read(b, off, len)
            if (n > 0) add(n.toLong())
            return n
        }
        private fun add(n: Long) {
            seen += n
            require(seen <= max) { "Signed archive exceeds the compressed size limit." }
        }
    }

    private val ALLOWED_NAMES = setOf("manifest.json", "manifest.sig", "hashes.hdb", "hashes.hsb", "hashes.sdb")
    private const val MAX_MANIFEST_BYTES = 8192
    private const val MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
    private const val MAX_ZIP_BYTES = 12L * 1024L * 1024L
}
