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
    fun completedVerdictsRemainCacheable() {
        listOf(ScanVerdict.NO_MATCH, ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS).forEach { verdict ->
            assertTrue(AppScanCachePolicy.canReuse(verdict))
            assertTrue(AppScanCachePolicy.shouldPersist(verdict))
        }
    }
}
