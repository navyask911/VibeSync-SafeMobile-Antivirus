package com.vibesync.antivirus.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalBaselineTrustTest {
    @Test fun lockedReleaseBuildWithAdbOffAndPlayServicesPasses() {
        val report = LocalBaselineTrust.evaluate(
            LocalBaselineObservations("release-keys", true, false, true)
        )
        assertTrue(report.trusted)
        assertTrue(report.reasons.isEmpty())
    }

    @Test fun testKeysFailTheLocalBaseline() {
        val report = LocalBaselineTrust.evaluate(
            LocalBaselineObservations("test-keys", true, false, true)
        )
        assertFalse(report.trusted)
        assertTrue(report.reasons.any { it.contains("test-keys") })
    }

    @Test fun unlockedBootloaderFailsTheLocalBaseline() {
        val report = LocalBaselineTrust.evaluate(
            LocalBaselineObservations("release-keys", false, false, true)
        )
        assertFalse(report.trusted)
        assertTrue(report.reasons.any { it.contains("Bootloader") })
    }

    @Test fun enabledAdbFailsTheLocalBaseline() {
        val report = LocalBaselineTrust.evaluate(
            LocalBaselineObservations("release-keys", true, true, true)
        )
        assertFalse(report.trusted)
        assertTrue(report.reasons.any { it.contains("ADB debugging is enabled") })
    }

    @Test fun unavailablePlayServicesFailTheLocalBaseline() {
        val report = LocalBaselineTrust.evaluate(
            LocalBaselineObservations("release-keys", true, false, false)
        )
        assertFalse(report.trusted)
        assertTrue(report.reasons.any { it.contains("Google Play Services is unavailable") })
    }

    @Test fun unreadableSignalsNeverEarnTrust() {
        val report = LocalBaselineTrust.evaluate(
            LocalBaselineObservations(null, null, null, null)
        )
        assertFalse(report.trusted)
        assertEquals(4, report.reasons.size)
    }

    @Test fun missingEndpointAlwaysUsesLocalBaseline() {
        assertTrue(LocalBaselineTrust.shouldUseLocalBaseline("", true))
        assertTrue(LocalBaselineTrust.shouldUseLocalBaseline("   ", true))
    }

    @Test fun offlineDeviceUsesLocalBaselineWithConfiguredEndpoint() {
        assertTrue(LocalBaselineTrust.shouldUseLocalBaseline("https://verify.example", false))
    }

    @Test fun onlineConfiguredEndpointKeepsRemoteFlow() {
        assertFalse(LocalBaselineTrust.shouldUseLocalBaseline("https://verify.example", true))
    }
}
