package com.vibesync.antivirus.core.worker

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanPublishPolicyTest {
    @Test fun zeroPersistedResultsMustFail() {
        assertTrue(ScanPublishPolicy.shouldFail(0, 0))
    }
    @Test fun anyPublishFailureMustFailEvenWhenSomeItemsPersisted() {
        assertTrue(ScanPublishPolicy.shouldFail(12, 1))
    }
    @Test fun persistedResultsWithoutPublishFailuresMaySucceed() {
        assertFalse(ScanPublishPolicy.shouldFail(12, 0))
    }
    @Test fun pendingVerdictsAreRetriedWithinConfiguredBudget() {
        assertTrue(ScanPublishPolicy.shouldRetry(4, 0, 2))
        assertTrue(ScanPublishPolicy.shouldRetry(1, 1, 2))
        assertFalse(ScanPublishPolicy.shouldRetry(1, 2, 2))
    }
    @Test fun completedOrEmptyVerdictsDoNotScheduleRetry() {
        assertFalse(ScanPublishPolicy.shouldRetry(0, 0))
    }
    @Test fun cleanRecentSessionMayDeduplicateWithinTheCooldown() {
        assertTrue(ScanPublishPolicy.shouldDeduplicate(10_000L, 11_000L, 0, 0, 120_000L))
    }
    @Test fun recentSessionWithPendingRetriesMustNotSuppressAnotherScan() {
        assertFalse(ScanPublishPolicy.shouldDeduplicate(10_000L, 11_000L, 3, 0, 120_000L))
    }
    @Test fun laterRetryAttemptMustNotBeDeduplicated() {
        assertFalse(ScanPublishPolicy.shouldDeduplicate(10_000L, 11_000L, 0, 1, 120_000L))
    }
}
