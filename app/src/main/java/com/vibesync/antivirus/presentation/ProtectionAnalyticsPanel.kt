package com.vibesync.antivirus.presentation

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.local.ScanAudit
import com.vibesync.antivirus.ui.components.EmptyState
import com.vibesync.antivirus.ui.components.SectionHeader
import com.vibesync.antivirus.ui.components.StatusChip
import com.vibesync.antivirus.ui.components.StatusKind
import java.text.DateFormat
import java.text.DateFormatSymbols
import java.util.Calendar
import java.util.Date

@Composable
internal fun ProtectionAnalyticsPanel(
    audits: List<ScanAudit>, results: List<ScanResult>, signatureCount: Int, activeIndicatorCount: Int,
    lastScanAt: Long?, isScanning: Boolean, quarantinedCount: Int, monitoringRunning: Boolean,
    storageAccessGranted: Boolean, notificationsGranted: Boolean, online: Boolean
) {
    val confirmed = audits.count { it.verdict == ScanVerdict.THREAT.name }
    val heuristic = audits.count { it.verdict == ScanVerdict.SUSPICIOUS.name }
    val incomplete = audits.count { it.verdict == ScanVerdict.NOT_SCANNED.name }
    val chartColor = MaterialTheme.colorScheme.primary
    Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
        SectionHeader(title = androidx.compose.ui.res.stringResource(R.string.analytics_title))
        Text(androidx.compose.ui.res.stringResource(R.string.analytics_subtitle),
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (isScanning) StatusChip(androidx.compose.ui.res.stringResource(R.string.analytics_scan_in_progress), kind = StatusKind.ACTIVE)
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            MetricCard(androidx.compose.ui.res.stringResource(R.string.analytics_audit_rows), audits.size.toString(), Modifier.weight(1f))
            MetricCard(androidx.compose.ui.res.stringResource(R.string.analytics_confirmed), confirmed.toString(), Modifier.weight(1f), danger = confirmed > 0)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
            MetricCard(androidx.compose.ui.res.stringResource(R.string.analytics_heuristic), heuristic.toString(), Modifier.weight(1f), warning = heuristic > 0)
            MetricCard(androidx.compose.ui.res.stringResource(R.string.analytics_not_scanned), incomplete.toString(), Modifier.weight(1f), warning = incomplete > 0)
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionHeader(title = androidx.compose.ui.res.stringResource(R.string.analytics_daily_activity))
                Text(androidx.compose.ui.res.stringResource(R.string.analytics_recent_window),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                val bars = recentDailyBars(audits)
                if (audits.isEmpty()) {
                    EmptyState(androidx.compose.ui.res.stringResource(R.string.analytics_no_audits),
                        androidx.compose.ui.res.stringResource(R.string.analytics_no_audits_body))
                } else {
                    val maxCount = (bars.maxOfOrNull { it.second } ?: 0).coerceAtLeast(1)
                    Canvas(Modifier.fillMaxWidth().height(100.dp)) {
                        val slot = size.width / bars.size
                        val barWidth = slot * 0.46f
                        bars.forEachIndexed { index, entry ->
                            val barHeight = size.height * entry.second.toFloat() / maxCount.toFloat()
                            drawRoundRect(chartColor,
                                topLeft = Offset(index * slot + (slot - barWidth) / 2f, size.height - barHeight),
                                size = Size(barWidth, barHeight.coerceAtLeast(if (entry.second == 0) 0f else 2.dp.toPx())),
                                cornerRadius = CornerRadius(4.dp.toPx()))
                        }
                    }
                    Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                        bars.forEach { (day, count) ->
                            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.weight(1f)) {
                                Text(count.toString(), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(day, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
            shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                SectionHeader(title = androidx.compose.ui.res.stringResource(R.string.analytics_protection_health))
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_definitions), signatureCount.toString(),
                    if (signatureCount > 0) StatusKind.ACTIVE else StatusKind.DANGER)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_feed_indicators), activeIndicatorCount.toString(), StatusKind.NEUTRAL)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_last_scan),
                    lastScanAt?.let { DateFormat.getDateTimeInstance().format(Date(it)) }
                        ?: androidx.compose.ui.res.stringResource(R.string.security_last_scan_none),
                    if (lastScanAt != null) StatusKind.SAFE else StatusKind.WARNING)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_storage),
                    androidx.compose.ui.res.stringResource(if (storageAccessGranted) R.string.analytics_access_available else R.string.analytics_limited),
                    if (storageAccessGranted) StatusKind.ACTIVE else StatusKind.WARNING)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_notifications),
                    androidx.compose.ui.res.stringResource(if (notificationsGranted) R.string.analytics_access_available else R.string.analytics_limited),
                    if (notificationsGranted) StatusKind.ACTIVE else StatusKind.WARNING)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_sentinel),
                    androidx.compose.ui.res.stringResource(if (monitoringRunning) R.string.analytics_sentinel_running else R.string.analytics_sentinel_stopped),
                    if (monitoringRunning) StatusKind.ACTIVE else StatusKind.WARNING)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_current_results), results.size.toString(), StatusKind.NEUTRAL)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_quarantine), quarantinedCount.toString(), StatusKind.NEUTRAL)
                HealthRow(androidx.compose.ui.res.stringResource(R.string.analytics_connection),
                    androidx.compose.ui.res.stringResource(if (online) R.string.analytics_online_local else R.string.analytics_offline_local), StatusKind.NEUTRAL)
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
            shape = RoundedCornerShape(18.dp), modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                SectionHeader(title = androidx.compose.ui.res.stringResource(R.string.analytics_recent_activity))
                if (audits.isEmpty()) {
                    EmptyState(androidx.compose.ui.res.stringResource(R.string.analytics_no_audits),
                        androidx.compose.ui.res.stringResource(R.string.analytics_no_audits_body))
                } else audits.take(8).forEach { audit ->
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        Icon(
                            imageVector = when (audit.verdict) {
                                ScanVerdict.THREAT.name, ScanVerdict.SUSPICIOUS.name -> Icons.Default.Warning
                                ScanVerdict.NO_MATCH.name -> Icons.Default.CheckCircle
                                else -> Icons.Default.History
                            },
                            contentDescription = null,
                            tint = when (audit.verdict) {
                                ScanVerdict.THREAT.name -> MaterialTheme.colorScheme.error
                                ScanVerdict.SUSPICIOUS.name -> MaterialTheme.colorScheme.tertiary
                                ScanVerdict.NO_MATCH.name -> Color(0xFF00A86B)
                                else -> MaterialTheme.colorScheme.onSurfaceVariant
                            }, modifier = Modifier.size(22.dp)
                        )
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(audit.packageOrPath, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(audit.verdict.replace('_', ' ').lowercase().replaceFirstChar { it.uppercase() },
                                style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Text(DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(audit.scanTimestamp)),
                            style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Text(androidx.compose.ui.res.stringResource(R.string.analytics_definition_note),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
@Composable
private fun MetricCard(label: String, value: String, modifier: Modifier = Modifier, danger: Boolean = false, warning: Boolean = false) {
    Card(modifier = modifier, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text(value, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold,
                color = when { danger -> MaterialTheme.colorScheme.error; warning -> MaterialTheme.colorScheme.tertiary; else -> MaterialTheme.colorScheme.onSurface })
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
@Composable
private fun HealthRow(label: String, value: String, kind: StatusKind) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f))
        Text(value, style = MaterialTheme.typography.labelMedium, color = when (kind) {
            StatusKind.DANGER -> MaterialTheme.colorScheme.error
            StatusKind.WARNING -> MaterialTheme.colorScheme.tertiary
            StatusKind.ACTIVE -> MaterialTheme.colorScheme.primary
            StatusKind.SAFE -> Color(0xFF00A86B)
            else -> MaterialTheme.colorScheme.onSurfaceVariant
        })
    }
}
private fun recentDailyBars(audits: List<ScanAudit>): List<Pair<String, Int>> {
    val labels = DateFormatSymbols.getInstance().shortWeekdays
    return (6 downTo 0).map { offset ->
        val start = Calendar.getInstance().apply {
            set(Calendar.HOUR_OF_DAY, 0); set(Calendar.MINUTE, 0); set(Calendar.SECOND, 0); set(Calendar.MILLISECOND, 0)
            add(Calendar.DAY_OF_YEAR, -offset)
        }
        val end = (start.clone() as Calendar).apply { add(Calendar.DAY_OF_YEAR, 1) }
        labels[start.get(Calendar.DAY_OF_WEEK)] to audits.count { it.scanTimestamp >= start.timeInMillis && it.scanTimestamp < end.timeInMillis }
    }
}
