package com.vibesync.antivirus.presentation

import android.content.Intent
import android.net.Uri
import androidx.annotation.StringRes
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Biotech
import androidx.compose.material.icons.outlined.CloudDownload
import androidx.compose.material.icons.outlined.Hub
import androidx.compose.material.icons.outlined.Insights
import androidx.compose.material.icons.outlined.Update
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.testTag
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard
import java.text.DateFormat
import java.text.NumberFormat
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle
import java.util.Date

private const val LIVE_DASHBOARD_URL = "https://navyask911.github.io/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/"

@Composable
internal fun ThreatIntelligenceCard(
    state: ThreatIntelligenceUiState = ThreatIntelligenceUiState(),
    onRefresh: () -> Unit = {},
    showRefreshAction: Boolean = false
) {
    ThreatIntelligenceCardContent(state, onRefresh, showRefreshAction)
}

/** Release-evaluation metrics and this device's local feed state are deliberately shown separately. */
@Composable
internal fun ThreatIntelligenceCardContent(
    state: ThreatIntelligenceUiState,
    onRefresh: () -> Unit = {},
    showRefreshAction: Boolean = false
) {
    val context = LocalContext.current
    val colors = MaterialTheme.colorScheme
    val locale = LocalConfiguration.current.locales[0]
    val integers = remember(locale) { NumberFormat.getIntegerInstance(locale) }
    val percent = remember(locale) {
        NumberFormat.getPercentInstance(locale).apply { maximumFractionDigits = 2 }
    }
    CyberCard(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(22.dp),
        colors = CardDefaults.cardColors(containerColor = colors.surface)) {
        Column(Modifier.background(Brush.linearGradient(listOf(
            colors.primaryContainer.copy(alpha = 0.55f), colors.surface
        ))).padding(18.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.background(colors.primary.copy(alpha = 0.12f), RoundedCornerShape(14.dp))
                    .padding(12.dp), contentAlignment = Alignment.Center) {
                    Icon(Icons.Outlined.Hub, contentDescription = null, tint = colors.primary,
                        modifier = Modifier.size(26.dp))
                }
                Text(stringResource(R.string.threat_intelligence_title), modifier = Modifier.weight(1f).semantics { heading() },
                    style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
            }
            val release = state.releaseStats
            if (release == null) {
                Text(
                    if (state.releaseStatsLoaded) stringResource(R.string.threat_intelligence_unavailable)
                    else stringResource(R.string.threat_intelligence_updating),
                    style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant
                )
            } else {
                IntelligenceMetric(R.string.threat_intelligence_samples, integers.format(release.totalMalwareSamples), Icons.Outlined.Biotech)
                IntelligenceMetric(R.string.threat_intelligence_accuracy, percent.format(release.accuracyFraction), Icons.Outlined.Insights)
                IntelligenceMetric(R.string.threat_intelligence_downloads, integers.format(release.totalDownloads), Icons.Outlined.CloudDownload)
                val updated = remember(release.lastUpdated, locale) {
                    runCatching {
                        DateTimeFormatter.ofLocalizedDateTime(FormatStyle.MEDIUM, FormatStyle.SHORT)
                            .withLocale(locale).format(OffsetDateTime.parse(release.lastUpdated)
                                .atZoneSameInstant(ZoneId.systemDefault()))
                    }.getOrElse {
                        DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM).withLocale(locale)
                            .format(LocalDate.parse(release.lastUpdated))
                    }
                }
                IntelligenceMetric(R.string.threat_intelligence_updated, updated, Icons.Outlined.Update)
                if (release.isStale) {
                    Text(stringResource(R.string.threat_intelligence_upstream_stale),
                        style = MaterialTheme.typography.labelMedium, color = colors.tertiary)
                }
            }

            if (state.feedStateLoaded) {
                HorizontalDivider(color = colors.primary.copy(alpha = 0.15f))
                Text(stringResource(R.string.threat_intelligence_device_title), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold)
                IntelligenceTextRow("Active local indicators",
                    state.activeLocalIndicatorCount?.let { integers.format(it.toLong()) } ?: "Not available")
                val status = state.feedSyncStatus?.replace('_', ' ')?.uppercase(locale) ?: "NO SYNC RECORD"
                IntelligenceTextRow("Configured feed status",
                    (if (state.feedIsStale) "STALE · " else "") + status)
                IntelligenceTextRow("Last successful sync",
                    state.feedLastSuccessAt?.let(::formatFeedTimestamp) ?: "Never recorded")
                state.feedLastAttemptAt?.let {
                    IntelligenceTextRow("Last sync attempt", formatFeedTimestamp(it))
                }
                state.feedImportedCount?.let {
                    IntelligenceTextRow("Indicators imported in latest sync", integers.format(it.toLong()))
                }
                state.feedSyncError?.takeIf { it.isNotBlank() }?.let {
                    Text(stringResource(R.string.threat_intelligence_latest_sync_note, it), style = MaterialTheme.typography.bodySmall,
                        color = colors.onSurfaceVariant)
                }
                if (state.feedIsStale) {
                    Text(stringResource(R.string.threat_intelligence_feed_stale),
                        style = MaterialTheme.typography.labelSmall, color = colors.tertiary)
                }
            }

            if (showRefreshAction) {
                TextButton(
                    onClick = onRefresh,
                    enabled = !state.isRefreshing,
                    modifier = Modifier.align(Alignment.Start).testTag("threat-intelligence.refresh")
                ) {
                    Text(if (state.isRefreshing) "Refreshing…" else "Refresh displayed stats")
                }
            }

            HorizontalDivider(color = colors.primary.copy(alpha = 0.15f))
            TextButton(onClick = {
                // Informational and user-initiated only; scanning stays offline.
                // The OS opens the external browser, not an in-app WebView.
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse(LIVE_DASHBOARD_URL))
                    .addCategory(Intent.CATEGORY_BROWSABLE)
                runCatching { context.startActivity(intent) }
            }, modifier = Modifier.align(Alignment.Start)) {
                Text(stringResource(R.string.threat_intelligence_live_dashboard_link),
                    style = MaterialTheme.typography.labelMedium)
            }
            Text(stringResource(R.string.threat_intelligence_training_note),
                style = MaterialTheme.typography.bodySmall, color = colors.onSurfaceVariant)
        }
    }
}

@Composable
private fun IntelligenceTextRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp),
        verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
    }
}

private fun formatFeedTimestamp(timestamp: Long): String =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(timestamp))

@Composable
private fun IntelligenceMetric(@StringRes label: Int, value: String, icon: ImageVector) {
    Row(Modifier.fillMaxWidth().semantics(mergeDescendants = true) {},
        horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(22.dp))
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(stringResource(label), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        }
    }
}
