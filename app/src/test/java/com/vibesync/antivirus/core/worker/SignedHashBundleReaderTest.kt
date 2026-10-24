package com.vibesync.antivirus.core.worker

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SignedHashBundleReaderTest {
    private val privateKey = Ed25519PrivateKeyParameters(ByteArray(32) { (it + 11).toByte() }, 0)
    private val publicKey = Base64.getEncoder().encodeToString(privateKey.generatePublicKey().encoded)
    private val body = "md5:".plus("a".repeat(32)).plus(":68:EICAR.Test\n").toByteArray()
    private fun signedZip(version: Long = 1L, payload: ByteArray = body, tamper: Boolean = false, unsigned: Boolean = false): ByteArray {
        val sha = MessageDigest.getInstance("SHA-256").digest(payload).joinToString("") { "%02x".format(it) }
        val manifest = JSONObject().put("schema_version", 1).put("version", version)
            .put("source_key", "b".repeat(64)).put("sha256", sha).put("format", "sdb")
            .toString().toByteArray()
        val signer = Ed25519Signer().apply { init(true, privateKey) }
        signer.update(manifest, 0, manifest.size)
        val sig = signer.generateSignature()
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            fun entry(name: String, bytes: ByteArray) {
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
            entry("manifest.json", manifest)
            if (!unsigned) entry("manifest.sig", sig)
            entry("hashes.sdb", if (tamper) payload + 0x21.toByte() else payload)
        }
        return out.toByteArray()
    }

    @Test fun validSignatureAndDigestAccepted() {
        val result = SignedHashBundleReader.read(ByteArrayInputStream(signedZip()), publicKey)
        assertEquals("sdb", result.format)
        assertEquals(1L, result.manifest.version)
        assertTrue(result.payload.contentEquals(body))
    }
    @Test fun tamperedPayloadRejected() {
        assertTrue(runCatching {
            SignedHashBundleReader.read(ByteArrayInputStream(signedZip(tamper = true)), publicKey)
        }.isFailure)
    }
    @Test fun unsignedBundleRejected() {
        assertTrue(runCatching {
            SignedHashBundleReader.read(ByteArrayInputStream(signedZip(unsigned = true)), publicKey)
        }.isFailure)
    }
    @Test fun missingTrustedKeyRejected() {
        assertTrue(runCatching {
            SignedHashBundleReader.read(ByteArrayInputStream(signedZip()), "")
        }.isFailure)
    }
    @Test fun invalidZipAndZipBombRejected() {
        assertTrue(runCatching { SignedHashBundleReader.read(ByteArrayInputStream(ByteArray(64)), publicKey) }.isFailure)
        val huge = ByteArrayOutputStream()
        ZipOutputStream(huge).use { zip ->
            zip.putNextEntry(ZipEntry("hashes.sdb"))
            zip.write(ByteArray(8 * 1024 * 1024 + 1))
            zip.closeEntry()
        }
        assertTrue(runCatching {
            SignedHashBundleReader.read(ByteArrayInputStream(huge.toByteArray()), publicKey)
        }.isFailure)
    }
}
