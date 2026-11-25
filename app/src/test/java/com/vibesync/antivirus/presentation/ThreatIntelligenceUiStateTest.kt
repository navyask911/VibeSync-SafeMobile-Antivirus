package com.vibesync.antivirus.presentation

import com.vibesync.antivirus.core.worker.ThreatIntelligenceStats
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import com.vibesync.antivirus.data.repository.ThreatFeedSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatIntelligenceUiStateTest {
    private val now = 1_800_000_000_000L

    @Test
    fun upstreamReleaseMetricsStayDistinctAndCarryTheirRealTimestamp() {
        val stats = ThreatIntelligenceStats(
            totalMalwareSamples = 5_560L,
            accuracyFraction = 0.9745,
            totalDownloads = 12_000L,
            lastUpdated = "2026-10-31T00:00:00Z"
        )
        val state = ThreatIntelligenceUiState().withReleaseStats(stats, now)

        assertTrue(state.releaseStatsLoaded)
        assertEquals(5_560L, state.releaseStats?.totalMalwareSamples)
        assertEquals(12_000L, state.releaseStats?.totalDownloads)
        assertEquals("2026-10-31T00:00:00Z", state.releaseStats?.lastUpdated)
        assertTrue(state.releaseStats?.isStale == true)
        assertNull(state.activeLocalIndicatorCount)
    }

    @Test
    fun aMissingReReadPreservesTheLastVerifiedUpstreamSnapshot() {
        val stats = ThreatIntelligenceStats(
            totalMalwareSamples = 5_560L,
            accuracyFraction = 0.9745,
            totalDownloads = 12_000L,
            lastUpdated = "2026-10-31T00:00:00Z"
        )
        val loaded = ThreatIntelligenceUiState().withReleaseStats(stats, now)
        val afterUnavailableRead = loaded.withReleaseStats(null, now + 1L)

        assertEquals(loaded.releaseStats, afterUnavailableRead.releaseStats)
        assertTrue(afterUnavailableRead.releaseStatsLoaded)
    }

    @Test
    fun roomFeedSnapshotMapsRealCountsStatusAndFreshness() {
        val lastSuccess = now - 8L * 24L * 60L * 60L * 1000L
        val sync = ThreatFeedSyncStateEntity(
            sourceKey = "source",
            sourceHost = "feed.example",
            lastAttemptAt = now - 1000L,
            lastSuccessAt = lastSuccess,
            status = "SUCCESS",
            lastImportedCount = 71
        )
        val state = ThreatIntelligenceUiState().withFeedSnapshot(
            ThreatFeedSnapshot(83, lastSuccess, sync),
            now
        )

        assertTrue(state.feedStateLoaded)
        assertEquals(83, state.activeLocalIndicatorCount)
        assertEquals("SUCCESS", state.feedSyncStatus)
        assertEquals(71, state.feedImportedCount)
        assertEquals(lastSuccess, state.feedLastSuccessAt)
        assertTrue(state.feedIsStale)
    }

    @Test
    fun missingSyncTimeRemainsUnknownRatherThanInventingAStaleTimestamp() {
        val state = ThreatIntelligenceUiState().withFeedSnapshot(
            ThreatFeedSnapshot(0, null, null),
            now
        )

        assertTrue(state.feedStateLoaded)
        assertEquals(0, state.activeLocalIndicatorCount)
        assertNull(state.feedLastSuccessAt)
        assertNull(state.feedSyncStatus)
        assertFalse(state.feedIsStale)
    }
}
