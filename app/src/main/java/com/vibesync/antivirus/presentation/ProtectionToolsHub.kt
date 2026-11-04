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
            Text(stringResource(R.string.tools_page_heading_ux),
                style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.tools_page_subtitle_ux),
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
                        Text(stringResource(R.string.tools_start_scan_ux),
                            style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                        Text(stringResource(R.string.tools_scan_description_ux),
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
                    Text(stringResource(R.string.tools_choose_apk_ux), modifier = Modifier.padding(start = 8.dp))
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.tools_watch_check_ux),
                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_install_sentinel), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.dashboard_install_sentinel_title, R.string.tools_install_sentinel_desc_ux,
                        stringResource(if (installSentinelActive) R.string.dashboard_status_on else R.string.dashboard_status_off)) { onOpen("sources") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_folder_monitor), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.dashboard_folder_monitoring_title, R.string.tools_folder_monitoring_desc_ux,
                        stringResource(if (foldersActive) R.string.dashboard_status_on else R.string.dashboard_status_off)) { onOpen("sentinel") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_link_checker), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.dashboard_link_checker_title, R.string.tools_link_checker_desc_ux,
                        stringResource(R.string.dashboard_status_on_demand)) { onOpen("phishing") }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.tools_review_manage_ux),
                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_device_posture), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.dashboard_device_posture_title, R.string.tools_posture_desc_ux,
                        stringResource(R.string.dashboard_status_review, pendingActions)) { onOpen("posture") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_apps), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.nav_apps, R.string.tools_apps_desc_ux,
                        if (inventoryLoaded) pluralStringResource(R.plurals.l10n_apps, installedAppsCount, installedAppsCount) else stringResource(R.string.apps_inventory_empty)) { onOpen("apps") }
                    ToolHubRow({ Icon(painterResource(R.drawable.ic_home_quarantine), null, tint = MaterialTheme.colorScheme.secondary) }, R.string.quarantine_vault_title, R.string.tools_quarantine_desc_ux,
                        pluralStringResource(R.plurals.l10n_files, quarantinedFilesCount, quarantinedFilesCount)) { onOpen("quarantine") }
                    ToolHubRow({ Icon(Icons.Outlined.History, null, tint = MaterialTheme.colorScheme.secondary) }, R.string.nav_history, R.string.tools_history_desc_ux,
                        stringResource(R.string.dashboard_view)) { onOpen("history") }
                    ToolHubRow({ Icon(Icons.Outlined.Assessment, null, tint = MaterialTheme.colorScheme.secondary) }, R.string.detection_capabilities_title, R.string.detection_capabilities_title,
                        stringResource(R.string.dashboard_view)) { onOpen("capabilities") }
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
            color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1,
            overflow = TextOverflow.Ellipsis)
    }
}
