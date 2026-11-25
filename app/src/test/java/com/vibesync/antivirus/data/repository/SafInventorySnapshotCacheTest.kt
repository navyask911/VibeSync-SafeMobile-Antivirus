package com.vibesync.antivirus.data.repository

import org.junit.Assert.assertEquals
import org.junit.Test

class SafInventorySnapshotCacheTest {
    @Test
    fun retryPassesReuseOneEnumerationForTheSameSessionAndRootSet() {
        val cache = SafInventorySnapshotCache<String>()
        var enumerations = 0
        val first = cache.getOrLoad("session-1", "root-A") {
            enumerations++
            listOf("file-1", "file-2")
        }
        val retry = cache.getOrLoad("session-1", "root-A") {
            enumerations++
            listOf("unexpected-duplicate")
        }
        assertEquals(listOf("file-1", "file-2"), first)
        assertEquals(first, retry)
        assertEquals(1, enumerations)
    }

    @Test
    fun changedRootSetRefreshesTheSessionInventory() {
        val cache = SafInventorySnapshotCache<String>()
        var enumerations = 0
        cache.getOrLoad("session-1", "root-A") { enumerations++; listOf("file-A") }
        val refreshed = cache.getOrLoad("session-1", "root-B") {
            enumerations++
            listOf("file-B")
        }
        assertEquals(listOf("file-B"), refreshed)
        assertEquals(2, enumerations)
    }

    @Test
    fun clearingATerminalSessionAllowsFreshEnumeration() {
        val cache = SafInventorySnapshotCache<String>()
        var enumerations = 0
        cache.getOrLoad("session-1", "root-A") { enumerations++; listOf("file-A") }
        cache.remove("session-1")
        val refreshed = cache.getOrLoad("session-1", "root-A") {
            enumerations++
            listOf("file-B")
        }
        assertEquals(listOf("file-B"), refreshed)
        assertEquals(2, enumerations)
    }
}
