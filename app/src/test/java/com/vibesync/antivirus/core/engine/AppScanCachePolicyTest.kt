package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppScanCachePolicyTest {
    @Test
    fun transientNotScannedVerdictsAreNeverReusedOrPersisted() {
        assertFalse(AppScanCachePolicy.canReuse(null))
        assertFalse(AppScanCachePolicy.canReuse(ScanVerdict.NOT_SCANNED))
        assertFalse(AppScanCachePolicy.shouldPersist(ScanVerdict.NOT_SCANNED))
    }

    @Test
    fun partialCoverageResultsAreNotPersistedInTheAppCache() {
        val partial = ScanResult(
            packageOrPath = "com.example.app",
            displayName = "Example",
            sha256 = "a".repeat(64),
            md5 = "b".repeat(32),
            verdict = ScanVerdict.NO_MATCH,
            reasons = listOf("YARA-X unavailable."),
            durationMs = 10L,
            analysisStages = listOf("HASH", "YARA_INCOMPLETE")
        )
        assertFalse(AppScanCachePolicy.shouldPersist(partial))
    }

    @Test
    fun completedVerdictsRemainCacheable() {
        listOf(ScanVerdict.NO_MATCH, ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS).forEach { verdict ->
            assertTrue(AppScanCachePolicy.canReuse(verdict))
            assertTrue(AppScanCachePolicy.shouldPersist(verdict))
        }
    }
}
