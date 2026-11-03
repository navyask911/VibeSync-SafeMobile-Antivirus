package com.vibesync.antivirus.presentation

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
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
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
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
    onPickApk: () -> Unit
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
                Button(onClick = onScanInstalled, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.scan_installed))
                }
                OutlinedButton(onClick = onPickApk, modifier = Modifier.fillMaxWidth()) {
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
                    ToolHubRow(Icons.Outlined.Security, R.string.nav_install_sources, R.string.install_sources_body) { onOpen("sources") }
                    ToolHubRow(Icons.Outlined.FolderOpen, R.string.nav_sentinel, R.string.monitor_explanation) { onOpen("sentinel") }
                    ToolHubRow(Icons.Outlined.Link, R.string.nav_phishing, R.string.phishing_disclaimer) { onOpen("phishing") }
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.about_legal),
                style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            CyberCard(modifier = Modifier.fillMaxWidth(), shape = SecurityTokens.cardShape) {
                Column(Modifier.padding(horizontal = 16.dp)) {
                    ToolHubRow(Icons.Outlined.Tune, R.string.posture_title, R.string.posture_risk_note) { onOpen("posture") }
                    ToolHubRow(Icons.Outlined.Apps, R.string.nav_apps, R.string.apps_inventory_empty_body) { onOpen("apps") }
                    ToolHubRow(Icons.Outlined.Storage, R.string.quarantine_vault_title, R.string.quarantine_vault_description) { onOpen("quarantine") }
                    ToolHubRow(Icons.Outlined.History, R.string.nav_history, R.string.history_empty) { onOpen("history") }
                    ToolHubRow(Icons.Outlined.Assessment, R.string.detection_capabilities_title, R.string.detection_capabilities_title) { onOpen("capabilities") }
                }
            }
        }
    }
}

@Composable
private fun ToolHubRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    titleResource: Int,
    bodyResource: Int,
    onClick: () -> Unit
) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Surface(shape = RoundedCornerShape(12.dp),
            color = MaterialTheme.colorScheme.secondaryContainer) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.secondary,
                modifier = Modifier.padding(9.dp).size(22.dp))
        }
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
            Text(stringResource(bodyResource), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}
