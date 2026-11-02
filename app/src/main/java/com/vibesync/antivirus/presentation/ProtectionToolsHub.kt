package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Apps
import androidx.compose.material.icons.outlined.Assessment
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Link
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Storage
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard

@Composable
internal fun ProtectionToolsHub(onOpen: (String) -> Unit) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.analytics_title), style = MaterialTheme.typography.titleLarge)
        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ToolHubRow(Icons.Outlined.Assessment, R.string.nav_analytics, R.string.analytics_subtitle) { onOpen("analytics") }
                ToolHubRow(Icons.Outlined.Apps, R.string.nav_apps, R.string.apps_inventory_empty_body) { onOpen("apps") }
                ToolHubRow(Icons.Outlined.Security, R.string.nav_install_sources, R.string.install_sources_body) { onOpen("sources") }
            }
        }
        CyberCard(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                ToolHubRow(Icons.Outlined.FolderOpen, R.string.nav_sentinel, R.string.monitor_explanation) { onOpen("sentinel") }
                ToolHubRow(Icons.Outlined.Link, R.string.nav_phishing, R.string.phishing_disclaimer) { onOpen("phishing") }
                ToolHubRow(Icons.Outlined.Storage, R.string.quarantine_vault_title, R.string.quarantine_vault_description) { onOpen("quarantine") }
                ToolHubRow(Icons.Outlined.History, R.string.nav_history, R.string.history_empty) { onOpen("history") }
                ToolHubRow(Icons.Outlined.Tune, R.string.detection_capabilities_title, R.string.detection_capabilities_title) { onOpen("capabilities") }
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
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(stringResource(titleResource), style = MaterialTheme.typography.bodyLarge)
            Text(stringResource(bodyResource), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2)
        }
        OutlinedButton(onClick = onClick) { Text(stringResource(R.string.posture_open)) }
    }
}
