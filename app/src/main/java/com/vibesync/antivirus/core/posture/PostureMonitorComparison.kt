package com.vibesync.antivirus.core.posture

/** Caller serializes access. State is saved before notifications, then each delivered event is acknowledged. */
class PostureMonitorComparison(private val store: PostureSnapshotStore) {
    fun check(report: DevicePostureReport, deliver: (PostureChange, PostureFinding) -> Boolean): PostureSnapshot {
        var next = PostureSnapshotComparison.advance(store.read() ?: PostureSnapshot(), report)
        store.write(next)
        for (change in next.pending.sortedBy { it.observedAt }) {
            if (change.capability.access in report.unavailable) continue
            val finding = report.findings.firstOrNull { it.access == change.capability.access &&
                it.packageName == change.capability.packageName && it.state == PostureGrantState.ENABLED } ?: continue
            if (deliver(change, finding)) {
                val acknowledged = next.copy(pending = next.pending - change)
                store.write(acknowledged)
                next = acknowledged
            }
        }
        return next
    }
}
