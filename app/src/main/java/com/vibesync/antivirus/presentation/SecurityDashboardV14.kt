package com.vibesync.antivirus.presentation

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
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
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.ads.AdMobManager
import com.vibesync.antivirus.ui.components.CyberCard
import com.vibesync.antivirus.ui.theme.SecurityTokens

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
    onQuarantine: () -> Unit,
    onOpenTools: () -> Unit = {}
) {
    val pendingIssue = advisor.critical.firstOrNull() ?: advisor.minor.firstOrNull()
    val interactionSource = remember { MutableInteractionSource() }
    val pressed by interactionSource.collectIsPressedAsState()
    val buttonScale by animateFloatAsState(
        targetValue = if (pressed) 0.98f else 1f,
        animationSpec = tween(110),
        label = stringResource(R.string.security_scan_now)
    )

    androidx.compose.foundation.lazy.LazyColumn(
        modifier = Modifier.fillMaxWidth(),
        contentPadding = PaddingValues(
            horizontal = SecurityTokens.pageHorizontalPadding,
            top = SecurityTokens.pageTopPadding,
            bottom = 24.dp
        ),
        verticalArrangement = Arrangement.spacedBy(SecurityTokens.sectionSpacing)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.security_dashboard_title),
                    style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.scan_explanation),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            CyberCard(
                modifier = Modifier.fillMaxWidth().animateContentSize(),
                shape = SecurityTokens.cardShape,
                elevation = CardDefaults.cardElevation(defaultElevation = SecurityTokens.cardElevation)
            ) {
                Column(Modifier.fillMaxWidth().padding(SecurityTokens.cardContentPadding),
                    verticalArrangement = Arrangement.spacedBy(SecurityTokens.cardInnerSpacing)) {
                    Row(verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(18.dp)) {
                        ProtectionScoreRing(advisor.score)
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text(stringResource(R.string.v140_security_risk_explained),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.secondary,
                                fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.v140_pending_actions, advisor.pendingCount),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold)
                            Text(stringResource(R.string.v140_security_risk_explained),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    if (pendingIssue != null) {
                        Surface(
                            modifier = Modifier.fillMaxWidth().clickable(onClick = onOpenAdvisor),
                            shape = SecurityTokens.tileShape,
                            color = MaterialTheme.colorScheme.surfaceVariant
                        ) {
                            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                                Icon(Icons.Outlined.Shield, contentDescription = null,
                                    tint = MaterialTheme.colorScheme.tertiary)
                                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text(stringResource(pendingIssue.titleResource),
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.SemiBold)
                                    Text(stringResource(pendingIssue.detailResource),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 3, overflow = TextOverflow.Ellipsis)
                                }
                            }
                        }
                    }
                    Button(
                        onClick = onScan,
                        enabled = !scanRunning,
                        interactionSource = interactionSource,
                        modifier = Modifier.fillMaxWidth().graphicsLayer {
                            scaleX = buttonScale
                            scaleY = buttonScale
                        }
                    ) {
                        if (scanRunning) CircularProgressIndicator(
                            Modifier.size(18.dp), strokeWidth = 2.dp,
                            color = MaterialTheme.colorScheme.onPrimary
                        ) else Icon(Icons.Outlined.Security, contentDescription = null)
                        Text(stringResource(if (scanRunning) R.string.scan_running else R.string.security_scan_now),
                            modifier = Modifier.padding(start = 8.dp))
                    }
                    if (scanRunning) {
                        Row(verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            if (scanProgress != null) CircularProgressIndicator(
                                progress = { scanProgress.coerceIn(0f, 1f) },
                                modifier = Modifier.size(18.dp), strokeWidth = 2.dp
                            )
                            Text(stringResource(R.string.scan_running),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    TextButton(onClick = onOpenAdvisor, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.v140_done_return_to_audit))
                    }
                }
            }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.nav_sentinel), modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    TextButton(onClick = onOpenTools) {
                        Text(stringResource(R.string.v140_analytics_tools))
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    QuickProtectionTool(Icons.Outlined.Shield, R.string.setup_sentinel_title,
                        if (installSentinelActive) R.string.ui_sentinel_running else R.string.ui_sentinel_setup,
                        onInstallSentinel, Modifier.weight(1f))
                    QuickProtectionTool(Icons.Outlined.FolderOpen, R.string.sentinel_scope_title,
                        if (downloadsActive || chatFoldersActive) R.string.ui_sentinel_running else R.string.ui_sentinel_setup,
                        onFolders, Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    QuickProtectionTool(Icons.Outlined.Link, R.string.nav_phishing,
                        R.string.phishing_assess, onLinkChecker, Modifier.weight(1f))
                    QuickProtectionTool(Icons.Outlined.SettingsSuggest, R.string.posture_title,
                        R.string.posture_refresh, onPosture, Modifier.weight(1f))
                }
            }
        }
        item {
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    DashboardActionRow(Icons.Outlined.Apps, R.string.nav_apps,
                        R.string.apps_inventory_empty_body, R.string.posture_open, onApps)
                    DashboardActionRow(Icons.Outlined.Storage, R.string.quarantine_vault_title,
                        R.string.quarantine_vault_description, R.string.posture_open, onQuarantine)
                    DashboardActionRow(Icons.Outlined.CleaningServices, R.string.cleaner_title,
                        R.string.cleaner_description, R.string.cleaner_scan_storage, onCleaner)
                }
            }
        }
        if (!isPro) {
            item {
                Surface(
                    modifier = Modifier.fillMaxWidth().clickable(onClick = onOpenPro),
                    shape = SecurityTokens.cardShape,
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
                ) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Icon(Icons.Outlined.Shield, contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary)
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(stringResource(R.string.pro_title),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.pro_feature_adfree),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(onClick = onOpenPro) {
                            Text(stringResource(R.string.posture_open))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun QuickProtectionTool(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    titleResource: Int,
    stateResource: Int,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.heightIn(min = 116.dp).clickable(onClick = onClick).animateContentSize(),
        shape = SecurityTokens.tileShape,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column(Modifier.fillMaxWidth().padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(36.dp).background(
                    MaterialTheme.colorScheme.secondaryContainer, SecurityTokens.iconTileShape
                ), contentAlignment = Alignment.Center) {
                    Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                }
                Spacer(Modifier.weight(1f))
                Text(stringResource(stateResource), style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
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
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(Modifier.size(40.dp).background(
            MaterialTheme.colorScheme.secondaryContainer, SecurityTokens.iconTileShape
        ), contentAlignment = Alignment.Center) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(stringResource(descriptionResource), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Text(stringResource(actionResource), style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
private fun ProtectionScoreRing(score: Int) {
    val sweep by animateFloatAsState(
        targetValue = score.coerceIn(0, 100) / 100f,
        animationSpec = tween(800),
        label = stringResource(R.string.device_security_score)
    )
    val track = MaterialTheme.colorScheme.surfaceVariant
    val accent = MaterialTheme.colorScheme.secondary
    Box(Modifier.size(108.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.size(108.dp)) {
            val stroke = 7.dp.toPx()
            val inset = stroke / 2f
            val arcSize = Size(size.width - stroke, size.height - stroke)
            val topLeft = Offset(inset, inset)
            drawArc(track, 0f, 360f, false, topLeft, arcSize, style = Stroke(stroke))
            drawArc(accent, -90f, sweep * 360f, false, topLeft, arcSize,
                style = Stroke(stroke, cap = StrokeCap.Round))
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(score.toString(), style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Text(stringResource(R.string.v140_completed), style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
