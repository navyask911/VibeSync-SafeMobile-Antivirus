package com.vibesync.antivirus.data.repository

/**
 * Keeps one bounded SAF file inventory per scan session. A root-set change invalidates
 * the snapshot; terminal/interrupted sessions explicitly remove it.
 */
internal class SafInventorySnapshotCache<T> {
    private data class Snapshot<T>(val rootsKey: String, val items: List<T>)
    private val snapshots = HashMap<String, Snapshot<T>>()

    @Synchronized
    fun getOrLoad(sessionId: String, rootsKey: String, load: () -> List<T>): List<T> {
        snapshots[sessionId]?.takeIf { it.rootsKey == rootsKey }?.let { return it.items }
        val loaded = load().toList()
        snapshots[sessionId] = Snapshot(rootsKey, loaded)
        return loaded
    }

    @Synchronized
    fun remove(sessionId: String) {
        snapshots.remove(sessionId)
    }

    @Synchronized
    fun clear() {
        snapshots.clear()
    }
}
