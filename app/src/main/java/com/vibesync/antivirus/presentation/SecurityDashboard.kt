package com.vibesync.antivirus.presentation

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
    val score by animateIntAsState(target, tween(900), label = "device-score-number")
    val progress by animateFloatAsState(target / 100f, tween(900), label = "device-score-gauge")
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
                        Text(if (assessment == null) "—" else score.toString(), style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
                        Text("/ 100", style = MaterialTheme.typography.labelMedium)
                    }
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Device Security Score", style = MaterialTheme.typography.titleLarge)
                    Text(if (assessment == null) "Checking device protection…" else
                        "Configuration score · ${4 - assessment.unknownChecks}/4 checks available",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            if (assessment != null) {
                val signals = assessment.signals
                ScoreRow("Play Protect (reported)", when(signals.playProtectEnabled) { true -> "On"; false -> "Off · −20"; null -> "Not verified" })
                ScoreRow("Threat database", if (assessment.databaseStale) "Missing or older than 24h · −10" else "Updated within 24h")
                ScoreRow("Non-system accessibility apps", signals.nonSystemAccessibilityApps?.let { "$it enabled" + if(it > 0) " · −20" else "" } ?: "Not available")
                ScoreRow("Non-system device administrators", signals.nonSystemDeviceAdmins?.let { "$it enabled" + if(it > 0) " · −20" else "" } ?: "Not available")
                Text("Starts at 100; each issue is deducted once. Unknown checks do not imply protection. Enabled accessibility and admin apps may be legitimate—review them before making changes.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = onCheckPlayProtect) { Text("Check Play Protect") }
                    if (assessment.databaseStale) TextButton(onClick = onSync) { Text("Update definitions") }
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
                    ScanProgressRing(progress, true, "Scan in progress", size = 96.dp)
                    Column(Modifier.weight(1f)) {
                        Text("Scanning your device", style = MaterialTheme.typography.titleLarge)
                        Text(if (state.totalItems > 0) "${state.processedItems} of ${state.totalItems} items checked" else "Preparing app inventory…")
                    }
                }
                TextButton(onClick = onCancel) { Text("Cancel scan") }
            } else if (summary != null) {
                Text("Scan Complete", style = MaterialTheme.typography.headlineSmall,
                    color = if (summary.threats > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
                Text("Scanned ${summary.appCount} apps · ${summary.fileCount} files.", style = MaterialTheme.typography.titleMedium)
                Text("${summary.threats} Threats Found", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                if (summary.review > 0 || summary.unreadable > 0) Text(
                    "${summary.review} items need review · ${summary.unreadable} could not be scanned.", color = MaterialTheme.colorScheme.tertiary)
                else if (summary.appCount + summary.fileCount == 0) Text("No readable items were available. Run another scan after selecting files or installing apps.")
                else if (summary.threats == 0) Text("No threats found in the items checked. A scan cannot guarantee that a device is risk-free.")
                if (!summary.signedDefinitionsUsed) Text("This scan ran without active signed threat definitions. Update definitions and scan again for full hash coverage.", color = MaterialTheme.colorScheme.tertiary)
                state.results.filter { it.verdict == ScanVerdict.THREAT }.take(3).forEach { Text("• ${it.displayName}", color = MaterialTheme.colorScheme.error) }
                Text(DateFormat.getDateTimeInstance().format(Date(summary.completedAt)), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                TextButton(onClick = onResults) { Text("View scan results") }
            }
        }
    }
}
