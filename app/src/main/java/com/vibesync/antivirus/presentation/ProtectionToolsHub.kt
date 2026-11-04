package com.vibesync.antivirus.presentation

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard
import com.vibesync.antivirus.ui.theme.SecurityTokens
import com.vibesync.antivirus.ui.theme.VibeSyncEmerald

@Composable
internal fun ProtectionToolsHub(
    onOpen: (String) -> Unit,
    onScanInstalled: () -> Unit,
    onPickApk: () -> Unit,
    installSentinelActive: Boolean = false,
    foldersActive: Boolean = false,
    pendingActions: Int = 0,
    installedAppsCount: Int = 0,
    inventoryLoaded: Boolean = false,
    quarantinedFilesCount: Int = 0
) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = SecurityTokens.pageHorizontalPadding, vertical = SecurityTokens.pageVerticalPadding),
        verticalArrangement = Arrangement.spacedBy(18.dp)
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(stringResource(R.string.analytics_title),
                style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.analytics_subtitle),
                style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
            Column(Modifier.fillMaxWidth().padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Surface(shape = SecurityTokens.iconTileShape,
                        color = MaterialTheme.colorScheme.secondaryContainer) {
                        Icon(Icons.Outlined.Security, contentDescription = null,
                            tint = MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.padding(10.dp).size(24.dp))
                    }
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(stringResource(R.string.security_scan_now),
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(stringResource(R.string.scan_explanation),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
                Button(onClick = onScanInstalled, shape = CircleShape,
                    modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    Text(stringResource(R.string.scan_installed))
                }
                Button(onClick = onPickApk, shape = CircleShape,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        contentColor = MaterialTheme.colorScheme.secondary
                    ), modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) {
                    Icon(Icons.Outlined.FolderOpen, contentDescription = null)
                    Text(stringResource(R.string.scan_selected), modifier = Modifier.padding(start = 8.dp))
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.nav_sentinel),
                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_install_sentinel), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.download_interceptor_label, R.string.install_sources_body,
                        stringResource(if (installSentinelActive) R.string.monitor_active else R.string.monitor_inactive),
                        if (installSentinelActive) VibeSyncEmerald else MaterialTheme.colorScheme.tertiary) { onOpen("sources") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_folder_monitor), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.sentinel_scope_title, R.string.monitor_explanation,
                        stringResource(if (foldersActive) R.string.monitor_active else R.string.monitor_inactive),
                        if (foldersActive) VibeSyncEmerald else MaterialTheme.colorScheme.tertiary) { onOpen("sentinel") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_link_checker), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.nav_phishing, R.string.phishing_disclaimer,
                        stringResource(R.string.feature_status_review), MaterialTheme.colorScheme.secondary) { onOpen("phishing") }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.nav_analytics),
                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_device_posture), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.posture_title, R.string.posture_risk_note,
                        stringResource(R.string.v140_pending_actions, pendingActions), MaterialTheme.colorScheme.tertiary) { onOpen("posture") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_apps), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.nav_apps, R.string.apps_inventory_empty_body,
                        if (inventoryLoaded) pluralStringResource(R.plurals.l10n_apps, installedAppsCount, installedAppsCount) else stringResource(R.string.apps_inventory_empty)) { onOpen("apps") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_quarantine), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.quarantine_vault_title, R.string.quarantine_vault_description,
                        pluralStringResource(R.plurals.l10n_files, quarantinedFilesCount, quarantinedFilesCount)) { onOpen("quarantine") }
                    ToolHubRow({ Icon(Icons.Outlined.History, null, tint = MaterialTheme.colorScheme.secondary) }, R.string.nav_history, R.string.history_empty,
                        stringResource(R.string.ui_view_scan_results)) { onOpen("history") }
                    ToolHubRow({ Icon(Icons.Outlined.Assessment, null, tint = MaterialTheme.colorScheme.secondary) }, R.string.detection_capabilities_title, R.string.detection_capabilities_title,
                        stringResource(R.string.ui_view_scan_results)) { onOpen("capabilities") }
                }
            }
        }
    }
}

@Composable
private fun ToolHubRow(
    icon: @Composable () -> Unit,
    titleResource: Int,
    bodyResource: Int,
    status: String,
    statusColor: Color = MaterialTheme.colorScheme.onSurfaceVariant,
    onClick: () -> Unit
) {
    Row(
        Modifier.fillMaxWidth().heightIn(min = 48.dp).clickable(onClick = onClick).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Surface(shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.secondaryContainer) {
            icon()
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(stringResource(bodyResource), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
        Text(status, style = MaterialTheme.typography.labelMedium,
            color = statusColor, maxLines = 1,
            overflow = TextOverflow.Ellipsis)
    }
}
