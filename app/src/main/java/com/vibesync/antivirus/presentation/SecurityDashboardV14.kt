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
import androidx.compose.foundation.shape.CircleShape
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
import androidx.compose.material3.ButtonDefaults
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.platform.LocalConfiguration
import java.text.DateFormat
import java.util.Date
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard
import com.vibesync.antivirus.ui.theme.SecurityTokens

@Composable
internal fun SecurityDashboardV14(
    advisor: ProtectionAdvisorState,
    isPro: Boolean,
    adsReady: Boolean,
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
    onOpenTools: () -> Unit = {},
    lastScanAt: Long? = null,
    reviewCount: Int = 0,
    onOpenScanResults: () -> Unit = {},
    installedAppsCount: Int = 0,
    inventoryLoaded: Boolean = false,
    quarantinedFilesCount: Int = 0
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
            vertical = SecurityTokens.pageVerticalPadding
        ),
        verticalArrangement = Arrangement.spacedBy(SecurityTokens.sectionSpacing)
    ) {
        item {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.security_dashboard_title),
                    style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.security_dashboard_subtitle),
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
                            Text(stringResource(R.string.device_security_score),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.secondary,
                                fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.v140_pending_actions, advisor.pendingCount),
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold)
                            Text(stringResource(R.string.v116_score_meaning),
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
                        shape = CircleShape,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = MaterialTheme.colorScheme.primary,
                            contentColor = MaterialTheme.colorScheme.onPrimary
                        ),
                        enabled = !scanRunning,
                        interactionSource = interactionSource,
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).graphicsLayer {
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
                                progress = scanProgress.coerceIn(0f, 1f),
                                modifier = Modifier.size(18.dp), strokeWidth = 2.dp
                            )
                            Text(stringResource(R.string.scan_running),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    val latestScanLabel = lastScanAt?.let { timestamp ->
                        DateFormat.getDateTimeInstance(
                            DateFormat.SHORT,
                            DateFormat.SHORT,
                            LocalConfiguration.current.locales[0]
                        ).format(Date(timestamp))
                    }
                    if (latestScanLabel != null) {
                        val scanSummary = stringResource(
                            R.string.format_label_value,
                            stringResource(R.string.history_title),
                            latestScanLabel
                        )
                        val reviewSummary = if (reviewCount > 0) {
                            pluralStringResource(R.plurals.l10n_review, reviewCount, reviewCount)
                        } else null
                        TextButton(onClick = onOpenScanResults, modifier = Modifier.fillMaxWidth()) {
                            Text(
                                listOfNotNull(scanSummary, reviewSummary).joinToString(" · "),
                                maxLines = 2,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                    } else {
                        TextButton(onClick = onOpenScanResults, modifier = Modifier.fillMaxWidth()) {
                            Text(stringResource(R.string.history_empty))
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
                    Text(stringResource(R.string.security_filter_overview), modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    TextButton(onClick = onOpenTools) {
                        Text(stringResource(R.string.v140_analytics_tools))
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    QuickProtectionTool(R.drawable.ic_home_install_sentinel, R.string.download_interceptor_label,
                        stringResource(if (installSentinelActive) R.string.monitor_active else R.string.monitor_inactive),
                        onInstallSentinel, Modifier.weight(1f))
                    QuickProtectionTool(R.drawable.ic_home_folder_monitor, R.string.sentinel_scope_title,
                        stringResource(if (downloadsActive || chatFoldersActive) R.string.monitor_active else R.string.monitor_inactive),
                        onFolders, Modifier.weight(1f))
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    QuickProtectionTool(R.drawable.ic_home_link_checker, R.string.nav_phishing,
                        stringResource(R.string.monitor_active_demand), onLinkChecker, Modifier.weight(1f))
                    QuickProtectionTool(R.drawable.ic_home_device_posture, R.string.posture_title,
                        stringResource(R.string.v140_pending_actions, advisor.pendingCount), onPosture, Modifier.weight(1f))
                }
            }
        }
        item {
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                    verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    DashboardActionRow({ Icon(painterResource(R.drawable.ic_home_apps), null, tint = MaterialTheme.colorScheme.secondary) },
                        R.string.nav_apps,
                        if (inventoryLoaded) pluralStringResource(R.plurals.l10n_apps, installedAppsCount, installedAppsCount) else stringResource(R.string.apps_inventory_empty),
                        stringResource(R.string.ui_view_scan_results), onApps)
                    DashboardActionRow({ Icon(painterResource(R.drawable.ic_home_quarantine), null, tint = MaterialTheme.colorScheme.secondary) },
                        R.string.quarantine_vault_title,
                        pluralStringResource(R.plurals.l10n_files, quarantinedFilesCount, quarantinedFilesCount),
                        stringResource(R.string.ui_view_scan_results), onQuarantine)
                    DashboardActionRow({ Icon(Icons.Outlined.CleaningServices, null, tint = MaterialTheme.colorScheme.secondary) },
                        R.string.cleaner_title,
                        stringResource(R.string.cleaner_description), stringResource(R.string.cleaner_scan_storage), onCleaner)
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
                            Text(stringResource(R.string.pro_truthful_summary),
                                style = MaterialTheme.typography.titleSmall,
                                fontWeight = FontWeight.Bold)
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
    iconResource: Int,
    titleResource: Int,
    stateLabel: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        modifier = modifier.heightIn(min = 116.dp).clickable(onClick = onClick).animateContentSize(),
        shape = SecurityTokens.tileShape,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline)
    ) {
        Column(Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(36.dp).background(
                    MaterialTheme.colorScheme.secondaryContainer, SecurityTokens.iconTileShape
                ), contentAlignment = Alignment.Center) {
                    Icon(painterResource(iconResource), contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                }
                Text(stateLabel, modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = androidx.compose.ui.text.style.TextAlign.End,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun DashboardActionRow(
    icon: @Composable () -> Unit,
    titleResource: Int,
    description: String,
    action: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(onClick = onClick).padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(Modifier.size(40.dp).background(
            MaterialTheme.colorScheme.secondaryContainer, SecurityTokens.iconTileShape
        ), contentAlignment = Alignment.Center) {
            icon()
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(description, style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Text(action, style = MaterialTheme.typography.labelMedium,
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
            Text(score.toString(), style = MaterialTheme.typography.headlineMedium.copy(
                fontSize = 48.sp, lineHeight = 52.sp
            ), fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface)
            Text(stringResource(R.string.ui_score_out_of_100),
                style = MaterialTheme.typography.labelMedium.copy(fontSize = 12.sp),
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
