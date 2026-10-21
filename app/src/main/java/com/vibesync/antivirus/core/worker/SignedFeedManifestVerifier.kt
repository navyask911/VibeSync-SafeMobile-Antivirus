package com.vibesync.antivirus.core.worker

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale

data class VerifiedFeedManifest(
    val version: Long,
    val sha256: String,
    val sourceKey: String,
    val rawManifestSha256: String
)

/**
 * Verifies a detached Ed25519 signature over the exact UTF-8 JSON bytes encoded in
 * X-SafeMobile-Manifest. The app expects a raw 32-byte Ed25519 public key encoded as base64.
 * No default key is bundled: a feed build without a configured trust root rejects all feeds.
 */
object SignedFeedManifestVerifier {
    const val MANIFEST_HEADER = "X-SafeMobile-Manifest"
    const val SIGNATURE_HEADER = "X-SafeMobile-Signature"
    private const val MAX_MANIFEST_BYTES = 8192
    private val SHA256 = Regex("^[a-f0-9]{64}$")

    fun verifyHeaders(
        manifestHeader: String?,
        signatureHeader: String?,
        publicKeyBase64: String?
    ): VerifiedFeedManifest {
        require(!manifestHeader.isNullOrBlank()) { "Signed feed manifest header is missing." }
        require(!signatureHeader.isNullOrBlank()) { "Detached feed signature header is missing." }
        require(!publicKeyBase64.isNullOrBlank()) { "No trusted Ed25519 feed verification key is configured." }
        val manifestBytes = Base64.getDecoder().decode(manifestHeader.trim())
        require(manifestBytes.isNotEmpty() && manifestBytes.size <= MAX_MANIFEST_BYTES) { "Feed manifest size is invalid." }
        val signatureBytes = Base64.getDecoder().decode(signatureHeader.trim())
        require(signatureBytes.size == 64) { "Ed25519 signature length is invalid." }
        val publicKey = Base64.getDecoder().decode(publicKeyBase64.trim())
        require(publicKey.size == 32) { "Ed25519 public key must be exactly 32 bytes." }

        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
        verifier.update(manifestBytes, 0, manifestBytes.size)
        require(verifier.verifySignature(signatureBytes)) { "Feed manifest signature verification failed." }

        val json = JSONObject(String(manifestBytes, StandardCharsets.UTF_8))
        require(json.optInt("schema_version", 0) == 1) { "Unsupported signed feed manifest schema." }
        val version = json.optLong("version", 0L)
        val hash = json.optString("sha256", "").lowercase(Locale.ROOT)
        val sourceKey = json.optString("source_key", "").lowercase(Locale.ROOT)
        require(version > 0L) { "Signed feed version must be positive." }
        require(SHA256.matches(hash)) { "Signed feed SHA-256 is missing or invalid." }
        require(SHA256.matches(sourceKey)) { "Signed feed source_key is missing or invalid." }
        return VerifiedFeedManifest(version, hash, sourceKey, sha256Hex(manifestBytes))
    }

    fun validateSourceAndVersion(manifest: VerifiedFeedManifest, expectedSourceKey: String, lastAcceptedVersion: Long) {
        require(SHA256.matches(expectedSourceKey.lowercase(Locale.ROOT))) { "Expected source key is invalid." }
        require(constantTimeHexEquals(manifest.sourceKey, expectedSourceKey.lowercase(Locale.ROOT))) {
            "Signed manifest belongs to a different feed URL."
        }
        require(manifest.version > lastAcceptedVersion) {
            "Signed feed replay or rollback rejected: version must be newer than the last accepted version."
        }
    }

    fun validatePayload(manifest: VerifiedFeedManifest, payloadSha256: String) {
        require(SHA256.matches(payloadSha256.lowercase(Locale.ROOT))) { "Downloaded feed digest is invalid." }
        require(constantTimeHexEquals(manifest.sha256, payloadSha256.lowercase(Locale.ROOT))) {
            "Downloaded feed SHA-256 does not match the signed manifest."
        }
    }

    private fun constantTimeHexEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(StandardCharsets.US_ASCII), right.toByteArray(StandardCharsets.US_ASCII))

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
