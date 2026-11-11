package com.vibesync.antivirus.core.posture

import java.io.IOException
import org.junit.Assert.*
import org.junit.Test

class PostureMonitorComparisonTest {
    private val finding = PostureFinding(PostureAccess.ACCESSIBILITY, "example.reader", "Reader", systemApp = false)
    private fun report(enabled: Boolean = true, unavailable: Boolean = false) = DevicePostureReport(
        if (enabled) listOf(finding) else emptyList(), if (unavailable) setOf(PostureAccess.ACCESSIBILITY) else emptySet(), 200L)
    private class MemoryStore(var value: PostureSnapshot? = PostureSnapshot(initialized = PostureSnapshotComparison.monitored)) : PostureSnapshotStore {
        var writes = 0
        var failWriteAt = -1
        override fun read() = value
        override fun write(snapshot: PostureSnapshot) {
            writes++
            if (writes == failWriteAt) throw IOException("Unavailable storage")
            value = snapshot
        }
    }

    @Test fun pendingEventIsDurableBeforeDeliveryAndAcknowledgedOnlyAfterSuccess() {
        val store = MemoryStore()
        var deliveries = 0
        val next = PostureMonitorComparison(store).check(report()) { change, observed ->
            assertTrue(change in store.value!!.pending)
            assertEquals(finding, observed)
            deliveries++
            true
        }
        assertEquals(1, deliveries)
        assertTrue(next.pending.isEmpty())
        PostureMonitorComparison(store).check(report()) { _, _ -> fail("Acknowledged events must not repeat"); false }
    }

    @Test fun deniedNotificationPermissionKeepsEventUntilDeliveryIsPossible() {
        val store = MemoryStore()
        val blocked = PostureMonitorComparison(store).check(report()) { _, _ -> false }
        assertEquals(1, blocked.pending.size)
        val delivered = PostureMonitorComparison(store).check(report()) { _, _ -> true }
        assertTrue(delivered.pending.isEmpty())
    }

    @Test fun revokedAccessCannotDeliverAnOldPendingAccusation() {
        val store = MemoryStore()
        PostureMonitorComparison(store).check(report()) { _, _ -> false }
        val next = PostureMonitorComparison(store).check(report(enabled = false)) { _, _ -> fail("Access was revoked"); true }
        assertTrue(next.pending.isEmpty())
    }

    @Test fun unavailableCategoryRetainsButDoesNotDeliverPendingChanges() {
        val store = MemoryStore()
        val first = PostureMonitorComparison(store).check(report()) { _, _ -> false }
        val partial = PostureMonitorComparison(store).check(report(unavailable = true)) { _, _ -> fail("Unconfirmed access"); true }
        assertEquals(first.pending, partial.pending)
    }

    @Test fun readFailureNeverOverwritesEncryptedBaseline() {
        var wrote = false
        val store = object : PostureSnapshotStore {
            override fun read(): PostureSnapshot? = throw IOException("Corrupt ciphertext")
            override fun write(snapshot: PostureSnapshot) { wrote = true }
        }
        try { PostureMonitorComparison(store).check(report()) { _, _ -> true }; fail("Read failure must propagate") }
        catch (_: IOException) { }
        assertFalse(wrote)
    }

    @Test fun writeFailurePreventsNotificationWithoutDurablePendingState() {
        val store = MemoryStore().also { it.failWriteAt = 1 }
        try { PostureMonitorComparison(store).check(report()) { _, _ -> fail("Not persisted"); true }; fail("Write failure must propagate") }
        catch (_: IOException) { }
        assertTrue(store.value!!.pending.isEmpty())
    }

    @Test fun acknowledgementFailureRetainsSameEventForIdempotentRetry() {
        val store = MemoryStore().also { it.failWriteAt = 2 }
        var delivered: PostureChange? = null
        try { PostureMonitorComparison(store).check(report()) { event, _ -> delivered = event; true }; fail("Acknowledgement must fail") }
        catch (_: IOException) { }
        assertEquals(delivered, store.value!!.pending.single())
    }

    @Test fun deliveryExceptionAlsoPreservesDurableEvent() {
        val store = MemoryStore()
        try { PostureMonitorComparison(store).check(report()) { _, _ -> throw SecurityException("Notifications blocked") }; fail("Expected delivery exception") }
        catch (_: SecurityException) { }
        assertEquals(1, store.value!!.pending.size)
    }
}
