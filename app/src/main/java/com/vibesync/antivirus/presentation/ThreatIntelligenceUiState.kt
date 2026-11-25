package com.vibesync.antivirus.presentation

import com.vibesync.antivirus.core.worker.ThreatIntelligenceFreshnessPolicy
import com.vibesync.antivirus.core.worker.ThreatIntelligenceStats
import com.vibesync.antivirus.data.repository.ThreatFeedSnapshot

/** Release-evaluation metrics are intentionally separate from this device's local definitions. */
data class ThreatIntelligenceReleaseStatsUi(
    val totalMalwareSamples: Long,
    val accuracyFraction: Double,
    val totalDownloads: Long,
    val lastUpdated: String,
    val isStale: Boolean
)

/** Observable presentation state for upstream research metrics and local feed state. */
data class ThreatIntelligenceUiState(
    val releaseStats: ThreatIntelligenceReleaseStatsUi? = null,
    val releaseStatsLoaded: Boolean = false,
    val isRefreshing: Boolean = false,
    val activeLocalIndicatorCount: Int? = null,
    val feedStateLoaded: Boolean = false,
    val feedSyncStatus: String? = null,
    val feedLastAttemptAt: Long? = null,
    val feedLastSuccessAt: Long? = null,
    val feedImportedCount: Int? = null,
    val feedSyncError: String? = null,
    val feedIsStale: Boolean = false
) {
    internal fun withReleaseStats(
        stats: ThreatIntelligenceStats?,
        nowMillis: Long = System.currentTimeMillis()
    ): ThreatIntelligenceUiState = copy(
        releaseStats = stats?.let {
            ThreatIntelligenceReleaseStatsUi(
                totalMalwareSamples = it.totalMalwareSamples,
                accuracyFraction = it.accuracyFraction,
                totalDownloads = it.totalDownloads,
                lastUpdated = it.lastUpdated,
                isStale = ThreatIntelligenceFreshnessPolicy.isUpstreamStatsStale(it, nowMillis)
            )
        },
        releaseStatsLoaded = true,
        isRefreshing = false
    )

    internal fun withFeedSnapshot(
        snapshot: ThreatFeedSnapshot,
        nowMillis: Long = System.currentTimeMillis()
    ): ThreatIntelligenceUiState = copy(
        activeLocalIndicatorCount = snapshot.activeIndicatorCount,
        feedStateLoaded = true,
        feedSyncStatus = snapshot.latestSyncState?.status,
        feedLastAttemptAt = snapshot.latestSyncState?.lastAttemptAt,
        feedLastSuccessAt = snapshot.lastSuccessfulSyncAt,
        feedImportedCount = snapshot.latestSyncState?.lastImportedCount,
        feedSyncError = snapshot.latestSyncState?.lastError,
        feedIsStale = ThreatIntelligenceFreshnessPolicy.isFeedStale(snapshot.lastSuccessfulSyncAt, nowMillis)
    )
}
