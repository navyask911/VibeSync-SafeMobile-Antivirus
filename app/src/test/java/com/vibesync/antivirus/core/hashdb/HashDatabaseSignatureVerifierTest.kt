package com.vibesync.antivirus.core.hashdb

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class HashDatabaseSignatureVerifierTest {
    @Test fun acceptsSignedBytesAndRejectsTamperingAndUnsignedInput() {
        val privateKey = Ed25519PrivateKeyParameters(ByteArray(32) { (it + 1).toByte() }, 0)
        val publicKey = privateKey.generatePublicKey().encoded
        val payload = "# SAFEHASH version=1 source=Test license=CC0-1.0\nmd5:44d88612fea8a8f36de82e1278abb02f:test\n".toByteArray()
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(payload, 0, payload.size)
        val signature = signer.generateSignature()
        val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey)

        assertTrue(HashDatabaseSignatureVerifier.verify(payload, signature, publicKeyBase64))
        assertFalse(HashDatabaseSignatureVerifier.verify(payload + byteArrayOf(0x0), signature, publicKeyBase64))
        assertFalse(HashDatabaseSignatureVerifier.verify(payload, ByteArray(0), publicKeyBase64))
        assertFalse(HashDatabaseSignatureVerifier.verify(payload, signature, ""))
    }
}
