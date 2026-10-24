package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.DetectionCoverage
import com.vibesync.antivirus.core.engine.DetectionLayerState
import com.vibesync.antivirus.core.engine.MetricsDocumentParser
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability

@Composable
fun DetectionCapabilitiesScreen(
    hashDatabaseCapability: HashDatabaseCapability,
    initialUpdateUrl: String,
    initialUpdatesEnabled: Boolean,
    onImportSignedDatabase: () -> Unit,
    onImportYaraRulesForReview: () -> Unit,
    onSaveUpdateConfiguration: (String, Boolean) -> Unit
) {
    val context = LocalContext.current
    var updateUrl by remember(initialUpdateUrl) { mutableStateOf(initialUpdateUrl) }
    var updatesEnabled by remember(initialUpdatesEnabled) { mutableStateOf(initialUpdatesEnabled) }
    val metricsMarkdown = remember(context) {
        runCatching { context.assets.open("METRICS.md").bufferedReader(Charsets.UTF_8).use { it.readText() } }
            .getOrElse { "**Status:** NOT MEASURED — the checked-in metrics document is unavailable. See docs/METRICS.md." }
    }
    val metrics = remember(metricsMarkdown) { MetricsDocumentParser.parse(metricsMarkdown) }
    val updateConfigurationAvailable = BuildConfig.OPTIONAL_FEED_ENABLED && BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.detection_capabilities_title), style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.detection_capabilities_description), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(stringResource(R.string.detection_capabilities_truth_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.detection_capabilities_truth_body), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                    Text(layer.id.replace('-', ' ').replaceFirstChar { it.uppercase() }, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(statusText, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    val reason = if (layer.id == "signed-multi-hash-database") {
                        "${hashDatabaseCapability.reason} Indicators: ${hashDatabaseCapability.indicatorCount}; version: ${hashDatabaseCapability.version ?: "none"}."
                    } else layer.reason
                    Text(reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.detection_capabilities_metrics_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                Text(metrics.status, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (metrics.reviewed.isNotBlank()) Text(metrics.reviewed, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                metrics.rows.forEach { metric ->
                    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                        Text(metric.metric, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        Text(metric.value, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                        Text(metric.interpretation, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
        }

        OutlinedButton(
            onClick = onImportSignedDatabase,
            enabled = BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED,
            modifier = Modifier.fillMaxWidth()
        ) { Text(stringResource(R.string.detection_capabilities_import_signed_db)) }
        OutlinedButton(onClick = onImportYaraRulesForReview, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.detection_capabilities_import_yara))
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                Text(stringResource(R.string.detection_capabilities_sync), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                if (updateConfigurationAvailable) {
                    OutlinedTextField(
                        value = updateUrl,
                        onValueChange = { updateUrl = it.take(2048) },
                        label = { Text(stringResource(R.string.detection_capabilities_feed_url)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                        Text(stringResource(R.string.detection_capabilities_sync_enabled), modifier = Modifier.weight(1f).padding(end = 8.dp), style = MaterialTheme.typography.bodyMedium)
                        Switch(checked = updatesEnabled, onCheckedChange = { updatesEnabled = it })
                    }
                    Button(
                        onClick = { onSaveUpdateConfiguration(updateUrl, updatesEnabled) },
                        enabled = (!updatesEnabled && updateUrl.isBlank()) || updateUrl.startsWith("https://", ignoreCase = true),
                        modifier = Modifier.fillMaxWidth()
                    ) { Text(stringResource(R.string.detection_capabilities_save)) }
                    Text(stringResource(R.string.detection_capabilities_sync_privacy), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text(stringResource(R.string.detection_capabilities_sync_unavailable), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}