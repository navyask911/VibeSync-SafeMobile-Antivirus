package com.vibesync.antivirus.core.security

import org.junit.Assert.*
import org.junit.Test

class DeviceSecurityScoreTest {
    private val now = 200_000_000L
    @Test fun allKnownSafeChecksScore100() {
        val result = DeviceSecurityScore.evaluate(DeviceSecuritySignals(true, now - 1, 0, 0), now)
        assertEquals(100, result.score)
        assertEquals(0, result.unknownChecks)
    }
    @Test fun deductionsApplyOncePerIssueNotPerApp() {
        val result = DeviceSecurityScore.evaluate(DeviceSecuritySignals(false, now - DeviceSecurityScore.FRESHNESS_MS, 7, 4), now)
        assertEquals(30, result.score)
    }
    @Test fun unknownStatusDoesNotClaimVerifiedProtection() {
        val result = DeviceSecurityScore.evaluate(DeviceSecuritySignals(), now)
        assertEquals(90, result.score)
        assertEquals(3, result.unknownChecks)
        assertTrue(result.databaseStale)
    }
    @Test fun freshnessBoundaryAndFutureDatesAreHandledConservatively() {
        assertFalse(DeviceSecurityScore.evaluate(DeviceSecuritySignals(databaseUpdatedAt = now - DeviceSecurityScore.FRESHNESS_MS + 1), now).databaseStale)
        assertTrue(DeviceSecurityScore.evaluate(DeviceSecuritySignals(databaseUpdatedAt = now - DeviceSecurityScore.FRESHNESS_MS), now).databaseStale)
        assertTrue(DeviceSecurityScore.evaluate(DeviceSecuritySignals(databaseUpdatedAt = now + 1), now).databaseStale)
    }
}
