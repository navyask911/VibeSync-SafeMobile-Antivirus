package com.vibesync.antivirus.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import com.vibesync.antivirus.ui.components.CyberCard as Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import kotlin.math.roundToInt

enum class StatusKind { ACTIVE, NEUTRAL, WARNING, DANGER, SAFE }

@Composable
fun StatusChip(label: String, kind: StatusKind = StatusKind.NEUTRAL, modifier: Modifier = Modifier) {
    val tint = when (kind) {
        StatusKind.ACTIVE -> MaterialTheme.colorScheme.primary
        StatusKind.NEUTRAL -> MaterialTheme.colorScheme.onSurfaceVariant
        StatusKind.WARNING -> MaterialTheme.colorScheme.tertiary
        StatusKind.DANGER -> MaterialTheme.colorScheme.error
        StatusKind.SAFE -> Color(0xFF00A86B)
    }
    Row(
        modifier = modifier.clip(RoundedCornerShape(8.dp)).background(tint.copy(alpha = 0.12f))
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        Box(Modifier.size(6.dp).clip(CircleShape).background(tint))
        Text(label, style = MaterialTheme.typography.labelMedium, color = tint, maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
fun SectionHeader(title: String, modifier: Modifier = Modifier, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
    Row(modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
        Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f))
        if (actionLabel != null && onAction != null) TextButton(onClick = onAction) { Text(actionLabel) }
    }
}

@Composable
fun EmptyState(title: String, description: String, modifier: Modifier = Modifier, actionLabel: String? = null, onAction: (() -> Unit)? = null) {
    Column(modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Box(Modifier.size(64.dp).clip(RoundedCornerShape(20.dp)).background(MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)),
            contentAlignment = Alignment.Center) {
            Icon(Icons.Default.FolderOpen, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(30.dp))
        }
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onSurface)
        Text(description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (actionLabel != null && onAction != null) Button(onClick = onAction) { Text(actionLabel) }
    }
}

@Composable
fun ScanProgressRing(progress: Float?, scanning: Boolean, label: String, modifier: Modifier = Modifier, size: Dp = 88.dp, success: Boolean = false) {
    val normalized = progress?.takeIf { it.isFinite() }?.coerceIn(0f, 1f)
    val animatedProgress by animateFloatAsState(normalized ?: 0f, animationSpec = tween(220), label = "scan-progress")
    val rotation = if (scanning && normalized == null) {
        val transition = rememberInfiniteTransition(label = "scan-radar")
        val animatedRotation by transition.animateFloat(0f, 360f,
            animationSpec = infiniteRepeatable(tween(1800, easing = LinearEasing)), label = "scan-radar-rotation")
        animatedRotation
    } else 0f
    val trackColor = MaterialTheme.colorScheme.surfaceVariant
    val primaryColor = MaterialTheme.colorScheme.primary
    val secondaryColor = MaterialTheme.colorScheme.secondary
    Box(modifier.size(size).semantics {
        contentDescription = if (normalized != null) label + ", " + (animatedProgress * 100f).roundToInt() + " percent" else label
        progressBarRangeInfo = if (normalized != null) ProgressBarRangeInfo(animatedProgress, 0f..1f)
            else if (scanning) ProgressBarRangeInfo.Indeterminate else ProgressBarRangeInfo(0f, 0f..1f)
    }, contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(size).graphicsLayer { rotationZ = rotation }) {
            val stroke = 6.dp.toPx()
            val inset = stroke / 2f
            val arcSize = androidx.compose.ui.geometry.Size(size.toPx() - stroke, size.toPx() - stroke)
            val topLeft = androidx.compose.ui.geometry.Offset(inset, inset)
            drawArc(trackColor, 0f, 360f, false, topLeft, arcSize, style = Stroke(width = stroke))
            if (normalized != null) {
                drawArc(primaryColor, -90f, animatedProgress * 360f, false, topLeft, arcSize,
                    style = Stroke(width = stroke, cap = StrokeCap.Round))
            } else if (scanning) {
                drawArc(Brush.sweepGradient(listOf(Color.Transparent, primaryColor,
                    secondaryColor.copy(alpha = 0.15f), Color.Transparent)),
                    -55f, 130f, false, topLeft, arcSize, style = Stroke(width = stroke, cap = StrokeCap.Round))
            }
        }
        Text(
            if (normalized != null) (animatedProgress * 100f).roundToInt().toString() + "%" else if (scanning) "..." else if (success) "✓" else "—",
            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold,
            color = if (normalized == null && !scanning && success) Color(0xFF00A86B)
                else if (normalized == null && !scanning) MaterialTheme.colorScheme.onSurfaceVariant
                else MaterialTheme.colorScheme.primary
        )
    }
}

@Composable
fun SecurityStatusCard(status: String, description: String, lastScanLabel: String, threatCount: Int,
    signatureCount: Int, scanning: Boolean, progress: Float?, hasScanned: Boolean, cleanResult: Boolean,
    onScan: () -> Unit, modifier: Modifier = Modifier) {
    Card(modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary.copy(alpha = 0.22f)),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
                ScanProgressRing(progress, scanning, status, size = 88.dp, success = cleanResult)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(status, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
                    Text(description, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(lastScanLabel, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                StatusChip(if (hasScanned) stringResource(R.string.ui_threats_found, threatCount) else stringResource(R.string.history_empty),
                    if (threatCount > 0) StatusKind.DANGER else StatusKind.NEUTRAL, Modifier.weight(1f))
                StatusChip(stringResource(R.string.threat_feed_active_count, signatureCount), if (signatureCount > 0) StatusKind.ACTIVE else StatusKind.WARNING, Modifier.weight(1f))
            }
            Button(onClick = onScan, modifier = Modifier.fillMaxWidth(), enabled = !scanning) {
                Icon(Icons.Default.Security, contentDescription = null)
                Spacer(Modifier.size(8.dp))
                Text(stringResource(R.string.scan_installed))
            }
        }
    }
}

@Composable
fun ThreatListItem(result: ScanResult, isProtectedSystemApp: Boolean, showUninstall: Boolean, showQuarantine: Boolean,
    showAppInfo: Boolean, onUninstall: (String) -> Unit, onAppInfo: (String) -> Unit, onQuarantine: () -> Unit,
    onTrust: (ScanResult) -> Unit = {}, modifier: Modifier = Modifier) {
    val kind = when (result.verdict) {
        ScanVerdict.THREAT -> StatusKind.DANGER
        ScanVerdict.SUSPICIOUS -> StatusKind.WARNING
        ScanVerdict.NO_MATCH -> StatusKind.SAFE
        ScanVerdict.NOT_SCANNED -> StatusKind.NEUTRAL
    }
    val verdictLabel = stringResource(when (result.verdict) {
        ScanVerdict.THREAT -> R.string.verdict_threat
        ScanVerdict.SUSPICIOUS -> R.string.verdict_suspicious
        ScanVerdict.NO_MATCH -> R.string.verdict_no_match
        ScanVerdict.NOT_SCANNED -> R.string.verdict_not_scanned
    })
    Card(modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(
                    imageVector = when (result.verdict) {
                        ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS, ScanVerdict.NOT_SCANNED -> Icons.Default.Warning
                        ScanVerdict.NO_MATCH -> Icons.Default.CheckCircle
                    },
                    contentDescription = null,
                    tint = when (kind) {
                        StatusKind.DANGER -> MaterialTheme.colorScheme.error
                        StatusKind.WARNING -> MaterialTheme.colorScheme.tertiary
                        StatusKind.SAFE -> Color(0xFF00A86B)
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    }, modifier = Modifier.size(28.dp)
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(result.displayName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(result.packageName ?: result.packageOrPath, style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
            }
            StatusChip(verdictLabel, kind)
            result.reasons.take(3).forEach { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            if (isProtectedSystemApp) Text(stringResource(R.string.uninstall_protected),
                style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                if (showAppInfo && isProtectedSystemApp && result.packageName != null) {
                    OutlinedButton(onClick = { onAppInfo(result.packageName) }, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.app_info_label))
                    }
                } else if (showUninstall && !isProtectedSystemApp && result.packageName != null) {
                    OutlinedButton(onClick = { onUninstall(result.packageName) }, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.uninstall_label))
                    }
                }
                if (result.packageName != null && result.sha256 != null &&
                    result.verdict == ScanVerdict.SUSPICIOUS && !isProtectedSystemApp) {
                    OutlinedButton(onClick = { onTrust(result) }, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.trusted_app_mark))
                    }
                }
                if (showQuarantine) {
                    OutlinedButton(onClick = onQuarantine, modifier = Modifier.weight(1f)) { Text(stringResource(R.string.quarantine_confirm_action)) }
                }
            }
        }
    }
}

