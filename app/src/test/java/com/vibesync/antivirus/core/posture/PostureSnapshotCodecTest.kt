package com.vibesync.antivirus.core.posture

import org.junit.Assert.*
import org.junit.Test

class PostureSnapshotCodecTest {
    private val grant = PostureCapability(PostureAccess.ACCESSIBILITY, "example.reader")
    private val snapshot = PostureSnapshot(PostureSnapshotComparison.monitored, setOf(grant), setOf(PostureChange(grant, 200)), 200)
    @Test fun roundTripRetainsPendingEventAndCoverage() {
        assertEquals(snapshot, PostureSnapshotCodec.decode(PostureSnapshotCodec.encode(snapshot)))
    }
    @Test fun unsupportedSchemaIsRejectedWithoutRebaselining() {
        reject(String(PostureSnapshotCodec.encode(snapshot)).replace("\"schema\":1", "\"schema\":2"))
    }
    @Test fun legacyDeviceAdminAndOverlayEntriesAreDiscardedWithoutLosingCurrentCoverage() {
        val legacy = """{"schema":1,"last_complete_check_at":300,"initialized":["ACCESSIBILITY","DEVICE_ADMIN","OVERLAY"],"grants":[{"access":"ACCESSIBILITY","package":"example.reader"},{"access":"DEVICE_ADMIN","package":"legacy.admin"},{"access":"OVERLAY","package":"legacy.overlay"}],"pending":[{"access":"DEVICE_ADMIN","package":"legacy.admin","observed_at":300}]}"""
        val decoded = PostureSnapshotCodec.decode(legacy.toByteArray())
        assertEquals(setOf(PostureAccess.ACCESSIBILITY), decoded.initialized)
        assertEquals(setOf(grant), decoded.grants)
        assertTrue(decoded.pending.isEmpty())
        assertEquals(300L, decoded.lastCompleteCheckAt)
    }
    @Test fun incompleteOrMalformedStateIsRejected() {
        reject("{}")
        reject("not-json")
        reject(String(PostureSnapshotCodec.encode(snapshot)).replace("example.reader", "../reader"))
        val invalid = snapshot.copy(grants = emptySet())
        reject(String(PostureSnapshotCodec.encode(invalid)))
    }
    private fun reject(text: String) {
        try { PostureSnapshotCodec.decode(text.toByteArray()); fail("Untrusted snapshot must be rejected") }
        catch (_: Exception) { }
    }
}
