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

    @Test fun allGoogleSystemAndBackgroundPackagesAreExcludedEvenWithTrustedSigners() {
        val systemFlags = android.content.pm.ApplicationInfo.FLAG_SYSTEM
        val updatedSystemFlags = android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        val googlePackages = listOf(
            "com.google.android.gms",
            "com.google.android.apps.fitness",
            "com.google.android.configupdater",
            "com.google.android.feedback",
            "com.google.android.setupwizard",
            "com.google.android.keyverification",
            "com.android.vending",
            "com.android.chrome"
        )
        for (packageName in googlePackages) {
            assertFalse("$packageName system", OfficialGoogleAppPolicy.isEligibleForInstalledScan(
                packageName, "com.vibesync.antivirus", systemFlags, officialGoogle = true
            ))
            assertFalse("$packageName updated system", OfficialGoogleAppPolicy.isEligibleForInstalledScan(
                packageName, "com.vibesync.antivirus", updatedSystemFlags, officialGoogle = true
            ))
            assertFalse("$packageName user flags", OfficialGoogleAppPolicy.isEligibleForInstalledScan(
                packageName, "com.vibesync.antivirus", 0, officialGoogle = true
            ))
        }
        assertFalse(OfficialGoogleAppPolicy.isEligibleForInstalledScan(
            "com.oem.settings", "com.vibesync.antivirus", systemFlags, officialGoogle = false
        ))
        assertFalse(OfficialGoogleAppPolicy.isEligibleForInstalledScan(
            "com.oem.settings", "com.vibesync.antivirus", updatedSystemFlags, officialGoogle = true
        ))
        assertTrue(OfficialGoogleAppPolicy.isEligibleForInstalledScan(
            "com.example.sideloaded", "com.vibesync.antivirus", 0, officialGoogle = false
        ))
        assertFalse(OfficialGoogleAppPolicy.isEligibleForInstalledScan(
            "com.vibesync.antivirus", "com.vibesync.antivirus", 0, officialGoogle = false
        ))
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
