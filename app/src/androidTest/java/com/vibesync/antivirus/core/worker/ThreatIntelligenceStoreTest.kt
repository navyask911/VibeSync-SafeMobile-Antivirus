package com.vibesync.antivirus.core.worker

import androidx.test.core.app.ApplicationProvider
import android.content.Context
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/** Real AtomicFile/FileObserver coverage on every supported CI emulator; no network or sample APKs. */
class ThreatIntelligenceStoreTest {
    private lateinit var root: File
    private lateinit var store: ThreatIntelligenceStore
    private fun fixture(downloads: Int) = """{"total_malware_samples":5560,"accuracy":97.45,"total_downloads":$downloads,"last_updated":"2026-10-31T00:00:00Z"}""".toByteArray()

    @Before fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        root = File(context.cacheDir, "stats-test-${System.nanoTime()}").apply { mkdirs() }
        store = ThreatIntelligenceStore(root)
    }
    @After fun cleanup() { root.deleteRecursively() }

    @Test fun missingOrCorruptFileHasNoInventedStatistics() {
        assertNull(store.read())
        val file = File(root, "ml-research-candidates/stats.json")
        file.parentFile!!.mkdirs()
        file.writeText("broken")
        assertNull(store.read())
        file.writeBytes(ByteArray(ThreatIntelligenceStats.MAX_BYTES + 1))
        assertNull(store.read())
    }

    @Test fun validSnapshotSurvivesRestartAndInvalidRefresh() {
        val bytes = fixture(21)
        assertTrue(store.write(bytes))
        assertFalse(store.write("{}".toByteArray()))
        assertEquals(21L, ThreatIntelligenceStore(root).read()!!.totalDownloads)
        assertArrayEquals(bytes, File(root, "ml-research-candidates/stats.json").readBytes())
    }

    @Test fun observerReloadsWhenWorkerReplacesCache() = runBlocking {
        store.write(fixture(21))
        val ready = CompletableDeferred<Unit>()
        val updated = async {
            withTimeout(10_000) {
                store.observe().first {
                    if (it?.totalDownloads == 21L) ready.complete(Unit)
                    it?.totalDownloads == 22L
                }
            }
        }
        withTimeout(10_000) { ready.await() }
        ThreatIntelligenceStore(root).write(fixture(22))
        assertEquals(22L, updated.await()!!.totalDownloads)
    }
}
