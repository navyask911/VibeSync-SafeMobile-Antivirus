package com.vibesync.antivirus.core.engine

import org.junit.Assert.*
import org.junit.Test

class ScanCompletionSummaryTest {
    private fun item(
        verdict: ScanVerdict,
        source: ScanSource = ScanSource.FRESH,
        apkBytes: Long? = 1L,
        app: Boolean = true
    ) = ScanResult(
        "fixture", "fixture", null, null, verdict, emptyList(), 1,
        packageName = if (app) "example.fixture" else null,
        apkSizeBytes = apkBytes,
        scanSource = source
    )

    @Test
    fun countsAppsCleanFilesAndIncompleteResultsWithoutClaimingClean() {
        val summary = ScanCompletionSummary.from(
            listOf(item(ScanVerdict.NO_MATCH), item(ScanVerdict.THREAT),
                item(ScanVerdict.NOT_SCANNED, app = false), item(ScanVerdict.SUSPICIOUS, app = false)),
            9, 1234
        )
        assertEquals(2, summary.appCount)
        assertEquals(7, summary.fileCount)
        assertEquals(1, summary.threats)
        assertEquals(1, summary.review)
        assertEquals(1, summary.unreadable)
        assertEquals(0, summary.pendingRetries)
    }

    @Test
    fun selectedFileWithNoProgressCallbackStillCountsOne() {
        val summary = ScanCompletionSummary.from(listOf(item(ScanVerdict.NO_MATCH, app = false)), 0, 1234)
        assertEquals(0, summary.appCount)
        assertEquals(1, summary.fileCount)
    }

    @Test
    fun calculatesFreshThroughputAndSeparatesCacheAndPendingRows() {
        val summary = ScanCompletionSummary.from(
            listOf(
                item(ScanVerdict.NO_MATCH, apkBytes = 2L * 1024L * 1024L),
                item(ScanVerdict.NO_MATCH, source = ScanSource.CACHE_HIT, apkBytes = 4096L),
                item(ScanVerdict.NOT_SCANNED, apkBytes = 1024L)
            ),
            processed = 3,
            now = 15_000L,
            startedAt = 10_000L,
            elapsedMsOverride = 5_000L,
            enumeratedPackages = 10,
            queuedPackages = 8,
            excludedPackages = 2
        )
        assertEquals(5_000L, summary.elapsedMs)
        assertEquals(2, summary.freshAppCount)
        assertEquals(1, summary.cachedAppCount)
        assertEquals(1, summary.pendingRetries)
        assertEquals(0.4, summary.appsPerSecond, 0.0001)
        assertTrue(summary.mbPerSecond > 0.0)
        assertEquals(2L * 1024L * 1024L + 4096L + 1024L, summary.totalApkBytes)
        assertEquals(2L * 1024L * 1024L + 1024L, summary.scannedApkBytes)
        assertEquals(10, summary.enumeratedPackages)
        assertEquals(8, summary.queuedPackages)
        assertEquals(2, summary.excludedPackages)
    }

    @Test
    fun emptyScanAndZeroElapsedTimeHaveZeroRates() {
        val summary = ScanCompletionSummary.from(
            emptyList(), processed = 0, now = 5_000L,
            startedAt = 5_000L, elapsedMsOverride = 0L
        )
        assertEquals(0.0, summary.appsPerSecond, 0.0)
        assertEquals(0.0, summary.mbPerSecond, 0.0)
        assertEquals(0L, summary.totalApkBytes)
        assertEquals(0L, summary.scannedApkBytes)
    }
}
