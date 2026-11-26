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
    fun successiveUpstreamSnapshotsReplaceMetricsAndRecomputeFreshness() {
        val first = ThreatIntelligenceStats(
            totalMalwareSamples = 5_560L,
            accuracyFraction = 0.9745,
            totalDownloads = 12_000L,
            lastUpdated = "2026-10-31T00:00:00Z"
        )
        val initial = ThreatIntelligenceUiState().withReleaseStats(first, now)
        assertTrue(initial.releaseStats?.isStale == true)

        val refreshedAt = java.time.OffsetDateTime.ofInstant(
            java.time.Instant.ofEpochMilli(now - 24L * 60L * 60L * 1000L),
            java.time.ZoneOffset.UTC
        ).toString()
        val refreshed = initial.withReleaseStats(
            ThreatIntelligenceStats(
                totalMalwareSamples = 6_100L,
                accuracyFraction = 0.981,
                totalDownloads = 12_500L,
                lastUpdated = refreshedAt
            ),
            now
        )

        assertEquals(6_100L, refreshed.releaseStats?.totalMalwareSamples)
        assertEquals(0.981, refreshed.releaseStats?.accuracyFraction!!, 0.000000001)
        assertEquals(12_500L, refreshed.releaseStats?.totalDownloads)
        assertEquals(refreshedAt, refreshed.releaseStats?.lastUpdated)
        assertFalse(refreshed.releaseStats?.isStale == true)
    }

    @Test
    fun successiveRoomSnapshotsReplaceRunningStateWithLatestSuccessfulFeedStats() {
        val running = ThreatFeedSyncStateEntity(
            sourceKey = "source",
            sourceHost = "feed.example",
            lastAttemptAt = now - 1_000L,
            status = "RUNNING"
        )
        val initial = ThreatIntelligenceUiState().withFeedSnapshot(
            ThreatFeedSnapshot(10, null, running),
            now
        )
        assertEquals(10, initial.activeLocalIndicatorCount)
        assertEquals("RUNNING", initial.feedSyncStatus)
        assertNull(initial.feedLastSuccessAt)

        val successAt = now - 500L
        val succeeded = initial.withFeedSnapshot(
            ThreatFeedSnapshot(
                activeIndicatorCount = 25,
                lastSuccessfulSyncAt = successAt,
                latestSyncState = running.copy(
                    lastAttemptAt = now,
                    lastSuccessAt = successAt,
                    status = "SUCCESS",
                    lastImportedCount = 25
                )
            ),
            now
        )

        assertEquals(25, succeeded.activeLocalIndicatorCount)
        assertEquals("SUCCESS", succeeded.feedSyncStatus)
        assertEquals(successAt, succeeded.feedLastSuccessAt)
        assertEquals(25, succeeded.feedImportedCount)
        assertFalse(succeeded.feedIsStale)
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
