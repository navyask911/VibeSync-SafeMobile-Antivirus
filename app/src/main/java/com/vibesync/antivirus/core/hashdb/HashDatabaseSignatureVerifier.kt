package com.vibesync.antivirus.core.hashdb

import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Verifies Ed25519 signatures over the exact original database bytes. */
object HashDatabaseSignatureVerifier {
    fun verify(databaseBytes: ByteArray, detachedSignatureBytes: ByteArray, publicKeyBase64: String): Boolean {
        if (databaseBytes.isEmpty() || publicKeyBase64.isBlank()) return false
        return try {
            val publicKey = Base64.getDecoder().decode(publicKeyBase64.trim())
            val signature = decodeSignature(detachedSignatureBytes)
            if (publicKey.size != 32 || signature.size != 64) return false
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(databaseBytes, 0, databaseBytes.size)
            verifier.verifySignature(signature)
        } catch (_: Exception) {
            false
        }
    }

    private fun decodeSignature(bytes: ByteArray): ByteArray {
        if (bytes.size == 64) return bytes
        val encoded = String(bytes, StandardCharsets.US_ASCII).trim()
        require(encoded.isNotEmpty() && encoded.length <= 256) { "Invalid detached signature encoding." }
        return Base64.getDecoder().decode(encoded)
    }
}
