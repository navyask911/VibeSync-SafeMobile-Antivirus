package com.vibesync.antivirus.core.engine

import org.junit.Assert.*
import org.junit.Test

class ScanCompletionSummaryTest {
    private fun item(verdict: ScanVerdict, app: Boolean = true) =
        ScanResult("fixture", "fixture", null, null, verdict, emptyList(), 1, packageName = if(app) "example.fixture" else null)
    @Test fun countsAppsCleanFilesAndIncompleteResultsWithoutClaimingClean() {
        val summary = ScanCompletionSummary.from(listOf(item(ScanVerdict.NO_MATCH), item(ScanVerdict.THREAT),
            item(ScanVerdict.NOT_SCANNED, false), item(ScanVerdict.SUSPICIOUS, false)), 9, 1234)
        assertEquals(2, summary.appCount)
        assertEquals(7, summary.fileCount)
        assertEquals(1, summary.threats)
        assertEquals(1, summary.review)
        assertEquals(1, summary.unreadable)
    }
    @Test fun selectedFileWithNoProgressCallbackStillCountsOne() {
        val summary = ScanCompletionSummary.from(listOf(item(ScanVerdict.NO_MATCH, false)), 0, 1234)
        assertEquals(0, summary.appCount)
        assertEquals(1, summary.fileCount)
    }
}
