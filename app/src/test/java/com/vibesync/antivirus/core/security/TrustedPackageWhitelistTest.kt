package com.vibesync.antivirus.core.security

import android.content.pm.ApplicationInfo
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TrustedPackageWhitelistTest {
    @Test fun systemAndUpdatedSystemPackagesAreNotReviewable() {
        assertTrue(TrustedPackageWhitelist.hasSystemFlags(ApplicationInfo.FLAG_SYSTEM))
        assertTrue(TrustedPackageWhitelist.hasSystemFlags(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP))
        assertFalse(ProtectedPackagePolicy.isUserInstalled(ApplicationInfo.FLAG_SYSTEM, "com.legitimate.camera"))
        assertFalse(ProtectedPackagePolicy.isUserInstalled(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP, "com.legitimate.calculator"))
    }

    @Test fun oppoColorOsAndAndroidGoogleNamespacesStayOutOfConsumerReview() {
        val system = listOf("com.oppo.camera", "com.oppo.market", "com.coloros.assistiveball",
            "com.oplus.launcher", "com.samsung.android.oneui", "com.miui.securitycenter",
            "com.android.calculator2", "com.google.android.projection.gearhead", "com.google.camera")
        for (name in system) {
            assertTrue(name, TrustedPackageWhitelist.hasProtectedNamespace(name))
            assertFalse(name, ProtectedPackagePolicy.isUserInstalled(0, name))
        }
    }


    @Test fun everyGoogleNamespaceIsExcludedRegardlessOfSignerOrInstallFlags() {
        val candidates = listOf(
            "com.google.android.gms",
            "com.google.android.apps.fitness",
            "com.google.android.configupdater",
            "com.google.android.feedback",
            "com.google.android.setupwizard",
            "com.google.android.keyverification",
            "com.android.vending",
            "com.android.chrome"
        )
        for (name in candidates) {
            assertTrue(name, TrustedPackageWhitelist.hasProtectedNamespace(name))
            assertFalse(name, TrustedPackageWhitelist.isEligibleForReview(
                name, "com.vibesync.antivirus", 0, officialGoogle = true
            ))
        }
    }

    @Test fun ordinarySideloadedAppIsStillReviewable() {
        val downloaded = "com.example.sideloaded.test"
        assertFalse(TrustedPackageWhitelist.hasProtectedNamespace(downloaded))
        assertTrue(ProtectedPackagePolicy.isUserInstalled(0, downloaded, "com.vibesync.antivirus"))
        assertFalse(ProtectedPackagePolicy.isUserInstalled(0, "com.vibesync.antivirus", "com.vibesync.antivirus"))
    }
}
