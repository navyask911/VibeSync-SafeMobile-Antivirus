package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Test

class ScanResultOrderingTest {
    private fun row(verdict: ScanVerdict, suffix: String) = ScanResult(
        packageOrPath = suffix,
        displayName = suffix,
        sha256 = null,
        md5 = null,
        verdict = verdict,
        reasons = emptyList(),
        durationMs = 1L,
        packageName = "com.example.\${suffix}"
    )

    @Test
    fun activeAndRestoredScanResultsUseTheSameSeverityOrder() {
        val ordered = ScanResultOrdering.sort(
            listOf(
                row(ScanVerdict.NO_MATCH, "clean"),
                row(ScanVerdict.NOT_SCANNED, "pending"),
                row(ScanVerdict.SUSPICIOUS, "review"),
                row(ScanVerdict.THREAT, "threat")
            )
        )
        assertEquals(
            listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS, ScanVerdict.NOT_SCANNED, ScanVerdict.NO_MATCH),
            ordered.map { it.verdict }
        )
    }
}
