package com.vibesync.antivirus.core.security

import org.junit.Assert.*
import org.junit.Test

class DeviceSecurityScoreTest {
    private val now = 200_000_000L

    @Test fun allObservedSafeSignalsScore100() {
        val signals = DeviceSecuritySignals(
            playProtectEnabled = true, databaseUpdatedAt = now - 1,
            nonSystemAccessibilityApps = 0, meetsDeviceIntegrity = true,
            usbDebuggingEnabled = false, safeMobileUnknownSourcesGrant = false,
            backgroundRestricted = false)
        val result = DeviceSecurityScore.evaluate(signals, now)
        assertEquals(100, result.score)
        assertEquals(0, result.unknownChecks)
    }

    @Test fun everyFactorDeductsExactlyItsDeclaredWeight() {
        val signals = DeviceSecuritySignals(
            playProtectEnabled = false, databaseUpdatedAt = null,
            nonSystemAccessibilityApps = 3, meetsDeviceIntegrity = false,
            usbDebuggingEnabled = true, safeMobileUnknownSourcesGrant = true,
            backgroundRestricted = true)
        assertEquals(0, DeviceSecurityScore.evaluate(signals, now).score)
    }

    @Test fun passingLocalBaselineEarnsIntegrityPointsWithoutClaimingRemoteVerdict() {
        val signals = DeviceSecuritySignals(
            playProtectEnabled = true,
            databaseUpdatedAt = now - 1,
            nonSystemAccessibilityApps = 0,
            meetsDeviceIntegrity = null,
            localBaselineTrusted = true,
            usbDebuggingEnabled = false,
            safeMobileUnknownSourcesGrant = false,
            backgroundRestricted = false
        )
        val result = DeviceSecurityScore.evaluate(signals, now)
        assertEquals(100, result.score)
        assertNull(signals.meetsDeviceIntegrity)
        assertEquals(true, signals.integrityCheckPassed)
        assertEquals(0, result.unknownChecks)
    }

    @Test fun failedLocalBaselineRetainsTheTwentyPointIntegrityDeduction() {
        val signals = DeviceSecuritySignals(
            playProtectEnabled = true,
            databaseUpdatedAt = now - 1,
            nonSystemAccessibilityApps = 0,
            meetsDeviceIntegrity = null,
            localBaselineTrusted = false,
            usbDebuggingEnabled = false,
            safeMobileUnknownSourcesGrant = false,
            backgroundRestricted = false
        )
        val result = DeviceSecurityScore.evaluate(signals, now)
        assertEquals(80, result.score)
        assertEquals(false, signals.integrityCheckPassed)
    }

    @Test fun unknownNeverCountsAsVerified() {
        val result = DeviceSecurityScore.evaluate(DeviceSecuritySignals(), now)
        assertEquals(70, result.score)
        assertEquals(6, result.unknownChecks)
        assertTrue(result.databaseStale)
    }

    @Test fun freshnessBoundaryAndFutureDatesAreHandledConservatively() {
        assertFalse(DeviceSecurityScore.evaluate(DeviceSecuritySignals(
            databaseUpdatedAt = now - DeviceSecurityScore.FRESHNESS_MS + 1), now).databaseStale)
        assertTrue(DeviceSecurityScore.evaluate(DeviceSecuritySignals(
            databaseUpdatedAt = now - DeviceSecurityScore.FRESHNESS_MS), now).databaseStale)
        assertTrue(DeviceSecurityScore.evaluate(DeviceSecuritySignals(
            databaseUpdatedAt = now + 1), now).databaseStale)
    }
}
