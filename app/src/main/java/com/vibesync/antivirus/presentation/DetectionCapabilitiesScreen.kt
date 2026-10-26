package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.DetectionCoverage
import com.vibesync.antivirus.core.engine.DetectionLayerState
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability

@Composable
fun DetectionCapabilitiesScreen(
    hashDatabaseCapability: HashDatabaseCapability,
    initialSyncPending: Boolean,
    onImportYaraRulesForReview: () -> Unit
) {
    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.detection_capabilities_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.detection_capabilities_description), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer), shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(stringResource(R.string.hash_database_sync_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(if (initialSyncPending) R.string.hash_database_initial_syncing else R.string.hash_database_sync_description),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.hash_database_sync_interval), style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary)
                Text(if (hashDatabaseCapability.enabled) {
                    "Active signed database · ${hashDatabaseCapability.indicatorCount} indicators · version ${hashDatabaseCapability.version ?: "—"}"
                } else hashDatabaseCapability.reason, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        DetectionCoverage.layers.forEach { layer ->
            val statusText = when (layer.id) {
                "signed-multi-hash-database" -> if (hashDatabaseCapability.enabled) stringResource(R.string.detection_capabilities_enabled) else stringResource(R.string.detection_capabilities_disabled)
                else -> when (layer.state) {
                    DetectionLayerState.ACTIVE_LIMITED -> stringResource(R.string.detection_capabilities_limited)
                    DetectionLayerState.HEURISTIC -> stringResource(R.string.detection_capabilities_advisory)
                    DetectionLayerState.DISABLED -> stringResource(R.string.detection_capabilities_disabled)
                    DetectionLayerState.CONDITIONAL -> stringResource(R.string.detection_capabilities_conditional)
                }
            }
            Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(layer.id.replace('-', ' ').replaceFirstChar { it.uppercase() }, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(statusText, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    val reason = if (layer.id == "signed-multi-hash-database") hashDatabaseCapability.reason else layer.reason
                    Text(reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        OutlinedButton(onClick = onImportYaraRulesForReview, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.detection_capabilities_import_yara))
        }
    }
}
