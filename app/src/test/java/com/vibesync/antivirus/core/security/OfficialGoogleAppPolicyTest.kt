package com.vibesync.antivirus.core.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfficialGoogleAppPolicyTest {
    @Test fun onlyGoogleNamespaceOrExplicitKnownPackagesAreCandidates() {
        assertTrue(OfficialGoogleAppPolicy.isGooglePackageName("com.google.android.apps.maps"))
        assertTrue(OfficialGoogleAppPolicy.isGooglePackageName("com.android.vending"))
        assertTrue(OfficialGoogleAppPolicy.isGooglePackageName("com.android.chrome"))
        assertFalse(OfficialGoogleAppPolicy.isGooglePackageName("com.example.google.maps"))
    }

    @Test fun packageNameAloneNeverEstablishesGoogleTrust() {
        val trusted = setOf("trusted-google-release-cert")
        assertFalse(OfficialGoogleAppPolicy.hasTrustedSigner(
            "com.google.android.apps.maps", setOf("attacker-cert"), trusted
        ))
        assertFalse(OfficialGoogleAppPolicy.hasTrustedSigner(
            "com.example.spoof", setOf("trusted-google-release-cert"), trusted
        ))
    }

    @Test fun officialGoogleCandidateRequiresMatchingTrustedSigner() {
        val trusted = setOf("trusted-google-release-cert")
        assertTrue(OfficialGoogleAppPolicy.hasTrustedSigner(
            "com.google.android.apps.maps",
            setOf("rotated-old-cert", "trusted-google-release-cert"),
            trusted
        ))
    }
}
