package com.vibesync.antivirus.presentation

import android.content.pm.ApplicationInfo
import com.vibesync.antivirus.core.security.ProtectedPackagePolicy
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SystemPackageGuardTest {
    @Test fun systemFlagsReturnBlocked() {
        assertTrue(SystemPackageGuard.evaluateFlags(ApplicationInfo.FLAG_SYSTEM) is PackageGuardResult.BlockedSystemApp)
        assertTrue(SystemPackageGuard.evaluateFlags(ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) is PackageGuardResult.BlockedSystemApp)
    }

    @Test fun ordinaryThirdPartyPackageIsEligible() {
        assertTrue(ProtectedPackagePolicy.isUserInstalled(ApplicationInfo.FLAG_HAS_CODE, "com.example.userapp"))
        assertTrue(ProtectedPackagePolicy.isUserInstalled(0, "com.example.userapp"))
    }

    @Test fun criticalServicesAreExcludedEvenWhenFlagsAreUnexpected() {
        listOf(
            "com.android.systemui",
            "com.google.android.gms",
            "com.android.vending",
            "com.android.carrierconfig"
        ).forEach { packageName ->
            assertFalse(ProtectedPackagePolicy.isUserInstalled(0, packageName))
        }
    }

    @Test fun appCannotOfferItselfForReviewOrRemoval() {
        assertFalse(ProtectedPackagePolicy.isUserInstalled(0, "com.example.security", "com.example.security"))
    }

    @Test fun deviceAdminIsBlocked() {
        assertTrue(SystemPackageGuard.evaluateFlags(0, isActiveDeviceAdmin = true) is PackageGuardResult.BlockedSystemApp)
    }

    @Test fun validatesPackageNames() {
        assertTrue(SystemPackageGuard.normalizePackageName(" com.example.userapp ") == "com.example.userapp")
        assertTrue(SystemPackageGuard.normalizePackageName("com.example..bad") == null)
        assertTrue(SystemPackageGuard.normalizePackageName("bad package") == null)
    }
}
