package com.vibesync.antivirus.presentation

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Analytics
import androidx.compose.material.icons.outlined.CleaningServices
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.SettingsSuggest
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.ads.AdMobManager
import com.vibesync.antivirus.ui.components.CyberCard

@Composable
internal fun SecurityDashboardV14(
    advisor: ProtectionAdvisorState,
    isPro: Boolean,
    adsReady: Boolean,
    adMobManager: AdMobManager,
    scanRunning: Boolean,
    scanProgress: Float?,
    downloadsActive: Boolean,
    chatFoldersActive: Boolean,
    installSentinelActive: Boolean,
    onOpenAdvisor: () -> Unit,
    onOpenPro: () -> Unit,
    onScan: () -> Unit,
    onCleaner: () -> Unit,
    onInstallSentinel: () -> Unit,
    onFolders: () -> Unit,
    onLinkChecker: () -> Unit,
    onPosture: () -> Unit,
    onApps: () -> Unit,
    onQuarantine: () -> Unit
) {
    androidx.compose.foundation.lazy.LazyColumn(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        if (!isPro) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth().animateContentSize().clickable(onClick = onOpenPro),
                    shape = CircleShape,
                    color = MaterialTheme.colorScheme.primaryContainer
                ) {
                    Row(Modifier.padding(horizontal = 16.dp, vertical = 11.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Outlined.Shield, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                        Text(stringResource(R.string.pro_title), modifier = Modifier.weight(1f).padding(start = 10.dp),
                            style = MaterialTheme.typography.bodyLarge)
                        Text(stringResource(R.string.about_legal), color = MaterialTheme.colorScheme.primary,
                            style = MaterialTheme.typography.labelLarge)
                    }
                }
            }
        }
        item {
            CyberCard(modifier = Modifier.fillMaxWidth().animateContentSize()) {
                Column(Modifier.padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    DualRingProtectionGauge(advisor.score)
                    Button(onClick = onOpenAdvisor, modifier = Modifier.fillMaxWidth()) {
                        Text(
                            if (advisor.pendingCount > 0)
                                stringResource(R.string.v140_pending_actions, advisor.pendingCount)
                            else stringResource(R.string.v140_done_return_to_audit)
                        )
                    }
                }
            }
        }
        item {
            CyberCard(modifier = Modifier.fillMaxWidth().animateContentSize()) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(stringResource(R.string.security_dashboard_title), style = MaterialTheme.typography.titleLarge,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (scanRunning) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            if (scanProgress != null) {
                                CircularProgressIndicator(
                                    progress = scanProgress.coerceIn(0f, 1f),
                                    modifier = Modifier.size(24.dp),
                                    strokeWidth = 2.dp
                                )
                            } else {
                                CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                            }
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                Text(stringResource(R.string.scan_running), style = MaterialTheme.typography.bodyMedium,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                scanProgress?.let { progress ->
                                    Text(
                                        stringResource(R.string.format_label_value, stringResource(R.string.analytics_scan_in_progress), "${(progress.coerceIn(0f, 1f) * 100).toInt()}%"),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                        }
                    }
                    val scanInteractionSource = remember { MutableInteractionSource() }
                    val scanPressed by scanInteractionSource.collectIsPressedAsState()
                    val scanButtonScale by animateFloatAsState(
                        targetValue = if (scanPressed) 0.98f else 1f,
                        animationSpec = tween(durationMillis = 110),
                        label = "scanNowScale"
                    )
                    Button(
                        onClick = onScan,
                        enabled = !scanRunning,
                        interactionSource = scanInteractionSource,
                        modifier = Modifier.fillMaxWidth().graphicsLayer {
                            scaleX = scanButtonScale
                            scaleY = scanButtonScale
                        }
                    ) {
                        Icon(Icons.Outlined.Security, contentDescription = null)
                        Text(stringResource(if (scanRunning) R.string.scan_running else R.string.security_scan_now),
                            modifier = Modifier.padding(start = 8.dp))
                    }
                    DashboardActionRow(
                        Icons.Outlined.CleaningServices, R.string.cleaner_title, R.string.cleaner_description,
                        R.string.cleaner_scan_storage, onCleaner
                    )
                }
            }
        }
        item {
            CyberCard(modifier = Modifier.fillMaxWidth().animateContentSize()) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(stringResource(R.string.nav_sentinel), style = MaterialTheme.typography.titleLarge,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    DashboardActionRow(
                        Icons.Outlined.Shield, R.string.setup_sentinel_title, R.string.setup_sentinel_body,
                        if (installSentinelActive) R.string.ui_sentinel_running else R.string.ui_sentinel_setup,
                        onInstallSentinel
                    )
                    DashboardActionRow(
                        Icons.Outlined.FolderOpen, R.string.sentinel_scope_title, R.string.monitor_explanation,
                        if (downloadsActive || chatFoldersActive) R.string.ui_sentinel_running else R.string.ui_sentinel_setup,
                        onFolders
                    )
                    DashboardActionRow(
                        Icons.Outlined.Link, R.string.nav_phishing, R.string.phishing_disclaimer,
                        R.string.phishing_assess, onLinkChecker
                    )
                }
            }
        }
        item {
            CyberCard(modifier = Modifier.fillMaxWidth().animateContentSize()) {
                Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(stringResource(R.string.posture_title), style = MaterialTheme.typography.titleLarge,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    DashboardActionRow(
                        Icons.Outlined.SettingsSuggest, R.string.posture_title, R.string.posture_risk_note,
                        R.string.posture_refresh, onPosture
                    )
                    DashboardActionRow(
                        Icons.Outlined.Analytics, R.string.nav_apps, R.string.apps_inventory_empty_body,
                        R.string.nav_apps, onApps
                    )
                    DashboardActionRow(
                        Icons.Outlined.Storage, R.string.quarantine_vault_title, R.string.quarantine_vault_description,
                        R.string.quarantine_vault_title, onQuarantine
                    )
                }
            }
        }
        if (!isPro && adsReady) {
            item {
                androidx.compose.foundation.layout.Box(Modifier.fillMaxWidth()) {
                    AdMobBanner(adMobManager)
                }
            }
        }
    }
}

@Composable
private fun DashboardActionRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    titleResource: Int,
    descriptionResource: Int,
    actionResource: Int,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp).animateContentSize(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Surface(shape = CircleShape, color = MaterialTheme.colorScheme.secondaryContainer, modifier = Modifier.size(42.dp)) {
            Box(contentAlignment = Alignment.Center) {
                Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
            }
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(stringResource(descriptionResource), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        androidx.compose.material3.TextButton(onClick = onClick) {
            Text(stringResource(actionResource), maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun DualRingProtectionGauge(score: Int) {
    val sweep by animateFloatAsState(targetValue = score.coerceIn(0, 100) / 100f, animationSpec = tween(950), label = stringResource(R.string.device_security_score))
    val trackColor = MaterialTheme.colorScheme.surfaceVariant
    val scoreColor = when {
        score < 50 -> MaterialTheme.colorScheme.error
        score < 80 -> Color(0xFFD97706)
        else -> Color(0xFF059669)
    }
    Box(contentAlignment = Alignment.Center, modifier = Modifier.size(222.dp)) {
        Canvas(Modifier.size(222.dp)) {
            val ringStroke = 8.dp.toPx()
            val centerInset = ringStroke / 2f
            val outerSize = Size(size.width - ringStroke, size.height - ringStroke)
            val outerStart = -117f
            val segmentColors = listOf(
                Color(0xFF0F2942), Color(0xFF0284C7), Color(0xFF059669), Color(0xFF64748B)
            )
            repeat(4) { index ->
                val start = outerStart + index * 90f
                drawArc(
                    color = trackColor,
                    startAngle = start,
                    sweepAngle = 55f,
                    useCenter = false,
                    topLeft = Offset(centerInset, centerInset),
                    size = outerSize,
                    style = Stroke(width = ringStroke, cap = StrokeCap.Round)
                )
                drawArc(
                    color = segmentColors[index],
                    startAngle = start,
                    sweepAngle = 55f,
                    useCenter = false,
                    topLeft = Offset(centerInset, centerInset),
                    size = outerSize,
                    style = Stroke(width = ringStroke, cap = StrokeCap.Round)
                )
            }
            val innerStroke = 15.dp.toPx()
            val innerInset = ringStroke + 8.dp.toPx()
            val innerSize = Size(size.width - innerInset * 2f, size.height - innerInset * 2f)
            drawArc(
                color = trackColor,
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = Offset(innerInset, innerInset),
                size = innerSize,
                style = Stroke(width = innerStroke, cap = StrokeCap.Round)
            )
            drawArc(
                color = scoreColor,
                startAngle = -90f,
                sweepAngle = 360f * sweep,
                useCenter = false,
                topLeft = Offset(innerInset, innerInset),
                size = innerSize,
                style = Stroke(width = innerStroke, cap = StrokeCap.Round)
            )
        }
        Column(
            modifier = Modifier.padding(horizontal = 28.dp, vertical = 18.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            Text(score.toString(), style = MaterialTheme.typography.displayLarge, color = MaterialTheme.colorScheme.onSurface)
            Text(stringResource(if (score >= 80) R.string.ui_status_safe else R.string.ui_status_at_risk),
                style = MaterialTheme.typography.titleMedium, color = scoreColor, maxLines = 1)
            Text(
                stringResource(R.string.ui_score_checks, score, 100),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
