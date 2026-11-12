package com.vibesync.antivirus.core.posture

import org.junit.Assert.*
import org.junit.Test

class PostureSnapshotComparisonTest {
    private val a = PostureFinding(PostureAccess.ACCESSIBILITY, "example.reader", "Reader", systemApp = false)
    private val listener = a.copy(access = PostureAccess.NOTIFICATION_LISTENER)
    private fun report(vararg findings: PostureFinding, unavailable: Set<PostureAccess> = emptySet(), at: Long = 100L) =
        DevicePostureReport(findings.toList(), unavailable, at)

    @Test fun firstCompleteSnapshotIsSilentEvenWithExistingPowerfulApps() {
        val first = PostureSnapshotComparison.advance(PostureSnapshot(), report(a, listener))
        assertEquals(PostureSnapshotComparison.monitored, first.initialized)
        assertEquals(2, first.grants.size)
        assertTrue(first.pending.isEmpty())
        assertEquals(100L, first.lastCompleteCheckAt)
    }

    @Test fun eachNewCapabilityCreatesOneChangeAndUnchangedReadsDoNotDuplicateIt() {
        val baseline = PostureSnapshotComparison.advance(PostureSnapshot(), report())
        val next = PostureSnapshotComparison.advance(baseline, report(a, listener, at = 200))
        assertEquals(2, next.pending.size)
        assertTrue(next.pending.all { it.observedAt == 200L })
        assertEquals(next.pending, PostureSnapshotComparison.advance(next, report(a, listener, at = 300)).pending)
    }

    @Test fun revocationDropsUndeliveredChangeAndLaterGrantIsANewEvent() {
        val baseline = PostureSnapshotComparison.advance(PostureSnapshot(), report())
        val granted = PostureSnapshotComparison.advance(baseline, report(a, at = 200))
        val revoked = PostureSnapshotComparison.advance(granted, report(at = 300))
        assertTrue(revoked.pending.isEmpty())
        assertTrue(revoked.grants.isEmpty())
        val again = PostureSnapshotComparison.advance(revoked, report(a, at = 400))
        assertEquals(400L, again.pending.single().observedAt)
    }

    @Test fun unreadableCategoriesPreserveBaselineAndDoNotInventRegrant() {
        val first = PostureSnapshotComparison.advance(PostureSnapshot(), report(a))
        val partial = PostureSnapshotComparison.advance(first,
            report(unavailable = setOf(PostureAccess.ACCESSIBILITY), at = 200))
        assertEquals(first.grants, partial.grants)
        assertEquals(100L, partial.lastCompleteCheckAt)
        assertTrue(PostureSnapshotComparison.advance(partial, report(a, at = 300)).pending.isEmpty())
    }

    @Test fun firstSuccessfulReadOfPreviouslyMissingCategoryIsItsSilentBaseline() {
        val first = PostureSnapshotComparison.advance(PostureSnapshot(), report(
            unavailable = setOf(PostureAccess.ACCESSIBILITY)))
        assertFalse(PostureAccess.ACCESSIBILITY in first.initialized)
        val next = PostureSnapshotComparison.advance(first, report(a))
        assertTrue(next.pending.isEmpty())
        assertEquals(PostureSnapshotComparison.monitored, next.initialized)
    }

    @Test fun multipleServicesInOneAppDoNotBecomeMultipleAppGrants() {
        val first = PostureSnapshotComparison.advance(PostureSnapshot(), report())
        val next = PostureSnapshotComparison.advance(first, report(a.copy(componentName = "example.reader/.One"),
            a.copy(componentName = "example.reader/.Two")))
        assertEquals(1, next.grants.size)
        assertEquals(1, next.pending.size)
    }

    @Test fun bothSystemMetadataAndProtectedVendorNamespacesSuppressRisk() {
        assertFalse(a.copy(packageName = "com.google.fake.reader").highRisk)
        assertFalse(a.copy(systemApp = true).highRisk)
        assertFalse(a.copy(systemApp = null).highRisk)
        assertEquals(1, report(a, listener).highRiskAppCount)
    }

    @Test fun staleRiskRemainsUntilItsCategoryCanConfirmRevocation() {
        val previous = report(a)
        val partial = report(unavailable = setOf(PostureAccess.ACCESSIBILITY)).retainingUnavailable(previous)
        assertEquals(1, partial.highRiskAppCount)
        assertTrue(partial.findings.single().stale)
        assertEquals(0, report().retainingUnavailable(partial).highRiskAppCount)
    }


}
