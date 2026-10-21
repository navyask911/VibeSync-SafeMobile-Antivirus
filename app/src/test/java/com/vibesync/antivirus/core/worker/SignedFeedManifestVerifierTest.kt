package com.vibesync.antivirus.core.worker

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.util.Base64

class SignedFeedManifestVerifierTest {
    private val privateKey = Ed25519PrivateKeyParameters(ByteArray(32) { (it + 1).toByte() }, 0)
    private val publicKeyBase64 = Base64.getEncoder().encodeToString(privateKey.generatePublicKey().encoded)
    private val sourceKey = "b".repeat(64)
    private val body = """[{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","threat_name":"fixture"}]""".toByteArray(Charsets.UTF_8)

    private fun signedHeaders(version: Long = 7L, payload: ByteArray = body): Pair<String, String> {
        val digest = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
        val manifest = JSONObject()
            .put("schema_version", 1)
            .put("version", version)
            .put("source_key", sourceKey)
            .put("sha256", digest)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(manifest, 0, manifest.size)
        return Base64.getEncoder().encodeToString(manifest) to Base64.getEncoder().encodeToString(signer.generateSignature())
    }

    @Test fun validDetachedSignaturePassesAndBindsSourceVersionAndBody() {
        val (manifestHeader, signatureHeader) = signedHeaders()
        val manifest = SignedFeedManifestVerifier.verifyHeaders(manifestHeader, signatureHeader, publicKeyBase64)
        SignedFeedManifestVerifier.validateSourceAndVersion(manifest, sourceKey, 6L)
        SignedFeedManifestVerifier.validatePayload(
            manifest, MessageDigest.getInstance("SHA-256").digest(body).joinToString("") { "%02x".format(it) }
        )
        assertEquals(7L, manifest.version)
    }

    @Test fun tamperedManifestIsRejected() {
        val (manifestHeader, signatureHeader) = signedHeaders()
        val manifestBytes = Base64.getDecoder().decode(manifestHeader).toString(Charsets.UTF_8)
        val tampered = manifestBytes.replace("\"version\":7", "\"version\":8")
        val thrown = runCatching {
            SignedFeedManifestVerifier.verifyHeaders(Base64.getEncoder().encodeToString(tampered.toByteArray()), signatureHeader, publicKeyBase64)
        }.isFailure
        assertTrue(thrown)
    }

    @Test fun unsignedFeedIsRejected() {
        assertTrue(runCatching {
            SignedFeedManifestVerifier.verifyHeaders(null, null, publicKeyBase64)
        }.isFailure)
    }

    @Test fun replayedVersionIsRejected() {
        val (m, s) = signedHeaders(version = 7L)
        val manifest = SignedFeedManifestVerifier.verifyHeaders(m, s, publicKeyBase64)
        assertTrue(runCatching { SignedFeedManifestVerifier.validateSourceAndVersion(manifest, sourceKey, 7L) }.isFailure)
        assertTrue(runCatching { SignedFeedManifestVerifier.validateSourceAndVersion(manifest, "c".repeat(64), 6L) }.isFailure)
    }

    @Test fun changedDownloadedBodyIsRejected() {
        val (m, s) = signedHeaders()
        val manifest = SignedFeedManifestVerifier.verifyHeaders(m, s, publicKeyBase64)
        val changed = body + byteArrayOf(0x20)
        val digest = MessageDigest.getInstance("SHA-256").digest(changed).joinToString("") { "%02x".format(it) }
        assertFalse(runCatching { SignedFeedManifestVerifier.validatePayload(manifest, digest) }.isSuccess)
    }
}
