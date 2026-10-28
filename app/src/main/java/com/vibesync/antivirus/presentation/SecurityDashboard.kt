package com.vibesync.antivirus.presentation

import androidx.compose.ui.res.pluralStringResource
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.security.DeviceSecurityAssessment
import com.vibesync.antivirus.ui.components.GlassCard
import com.vibesync.antivirus.ui.components.ScanProgressRing
import java.text.DateFormat
import java.util.Date

@Composable
internal fun SecurityDashboard(assessment: DeviceSecurityAssessment?, onCheckPlayProtect: () -> Unit, onSync: () -> Unit) {
    val target = assessment?.score ?: 0
    val score by animateIntAsState(target, tween(900))
    val progress by animateFloatAsState(target / 100f, tween(900))
    GlassCard(Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(18.dp)) {
                val accent = if (target >= 90) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary
                val track = MaterialTheme.colorScheme.surfaceVariant
                Box(Modifier.size(110.dp).semantics { progressBarRangeInfo = ProgressBarRangeInfo(progress, 0f..1f) }, contentAlignment = Alignment.Center) {
                    Canvas(Modifier.size(106.dp)) {
                        val stroke = 8.dp.toPx(); val inset = stroke / 2
                        val arcSize = androidx.compose.ui.geometry.Size(size.width - stroke, size.height - stroke)
                        drawArc(track, -90f, 360f, false, Offset(inset, inset), arcSize, style = Stroke(stroke))
                        drawArc(accent, -90f, progress * 360f, false, Offset(inset, inset), arcSize, style = Stroke(stroke, cap = StrokeCap.Round))
                    }
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(if (assessment == null) "—" else localizedNumber(score), style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
                        Text(stringResource(R.string.ui_score_out_of_100), style = MaterialTheme.typography.labelMedium)
                    }
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(stringResource(R.string.ui_score_title), style = MaterialTheme.typography.titleLarge)
                    Text(if (assessment == null) stringResource(R.string.ui_score_checking) else
                        stringResource(R.string.ui_score_checks, 4 - assessment.unknownChecks, 4),
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (assessment != null) {
                val signals = assessment.signals
                ScoreRow(stringResource(R.string.ui_score_play_protect), when(signals.playProtectEnabled) { true -> stringResource(R.string.ui_on); false -> stringResource(R.string.ui_off_20); null -> stringResource(R.string.ui_not_verified) })
                ScoreRow(stringResource(R.string.ui_score_database), if (assessment.databaseStale) stringResource(R.string.ui_stale_10) else stringResource(R.string.ui_updated_24))
                ScoreRow(stringResource(R.string.ui_score_accessibility), signals.nonSystemAccessibilityApps?.let { pluralStringResource(R.plurals.l10n_enabled_apps, it, it) + if(it > 0) stringResource(R.string.ui_penalty_20) else "" } ?: stringResource(R.string.ui_unavailable))
                ScoreRow(stringResource(R.string.ui_score_admin), signals.nonSystemDeviceAdmins?.let { pluralStringResource(R.plurals.l10n_enabled_apps, it, it) + if(it > 0) stringResource(R.string.ui_penalty_20) else "" } ?: stringResource(R.string.ui_unavailable))
                Text(stringResource(R.string.ui_score_explanation),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onCheckPlayProtect) { Text(stringResource(R.string.ui_check_play_protect)) }
                    if (assessment.databaseStale) TextButton(onClick = onSync) { Text(stringResource(R.string.ui_update_definitions)) }
                }
            }
        }
    }
}

@Composable
private fun ScoreRow(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
internal fun ScanFeedbackCard(state: SafeMobileUiState, onResults: () -> Unit, onCancel: () -> Unit) {
    val summary = state.scanSummary
    if (!state.isScanning && summary == null) return
    GlassCard(Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (state.isScanning) {
                val progress = if (state.totalItems > 0) (state.processedItems.toFloat() / state.totalItems).coerceIn(0f, 1f) else null
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    ScanProgressRing(progress, true, stringResource(R.string.ui_scanning_progress), size = 96.dp)
                    Column(Modifier.weight(1f)) {
                        Text(stringResource(R.string.ui_scanning_title), style = MaterialTheme.typography.titleLarge)
                        Text(if (state.totalItems > 0) pluralStringResource(R.plurals.l10n_progress, state.totalItems, state.processedItems, state.totalItems) else stringResource(R.string.ui_preparing_inventory))
                    }
                }
                TextButton(onClick = onCancel) { Text(stringResource(R.string.ui_cancel_scan)) }
            } else if (summary != null) {
                Text(stringResource(R.string.scan_complete), style = MaterialTheme.typography.headlineSmall,
                    color = if (summary.threats > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                Text(listOf(pluralStringResource(R.plurals.l10n_scanned_apps, summary.appCount, summary.appCount), pluralStringResource(R.plurals.l10n_scanned_files, summary.fileCount, summary.fileCount)).joinToString(" · "), style = MaterialTheme.typography.titleMedium)
                Text(pluralStringResource(R.plurals.l10n_threats, summary.threats, summary.threats), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                if (summary.review > 0 || summary.unreadable > 0) Text(
                    listOf(pluralStringResource(R.plurals.l10n_review, summary.review, summary.review), pluralStringResource(R.plurals.l10n_unreadable, summary.unreadable, summary.unreadable)).joinToString(" · "), color = MaterialTheme.colorScheme.tertiary)
                else if (summary.appCount + summary.fileCount == 0) Text(stringResource(R.string.ui_no_readable_items))
                else if (summary.threats == 0) Text(stringResource(R.string.system_app_scan_complete))
                if (!summary.signedDefinitionsUsed) Text(stringResource(R.string.ui_unsigned_definitions_warning), color = MaterialTheme.colorScheme.tertiary)
                state.results.filter { it.verdict == ScanVerdict.THREAT }.take(3).forEach { Text(stringResource(R.string.format_bullet, it.displayName), color = MaterialTheme.colorScheme.error) }
                Text(localizedDate(summary.completedAt), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TextButton(onClick = onResults) { Text(stringResource(R.string.ui_view_scan_results)) }
            }
        }
    }
}
