package com.vibesync.antivirus.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineAttestationTest {
    @Test fun signerPinMustBeValidSha256() {
        assertEquals("a".repeat(64), OfflineAttestation.normalizeSha256("A".repeat(64)))
        assertEquals(null, OfflineAttestation.normalizeSha256(""))
        assertEquals(null, OfflineAttestation.normalizeSha256("not-a-digest"))
    }
    @Test fun sha256UsesExpectedDigestForKnownTestBytes() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            OfflineAttestation.sha256Hex("abc".toByteArray()))
    }
    @Test fun digestComparisonRejectsTamperedValues() {
        val d = "a".repeat(64)
        assertTrue(OfflineAttestation.constantTimeEqualsHex(d, d))
        assertFalse(OfflineAttestation.constantTimeEqualsHex(d, "b".repeat(64)))
    }
}
