package com.vibesync.antivirus.presentation

import androidx.compose.ui.platform.LocalContext
import com.vibesync.antivirus.core.locale.SecurityText
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import com.vibesync.antivirus.ui.components.CyberCard as Card
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
import com.vibesync.antivirus.core.engine.BundledYaraEngine
import com.vibesync.antivirus.core.engine.DetectionCoverage
import com.vibesync.antivirus.core.engine.DetectionLayerState
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability

@Composable
fun DetectionCapabilitiesScreen(
    hashDatabaseCapability: HashDatabaseCapability,
    initialSyncPending: Boolean,
    yaraMatchCount: Int = 0,
    yaraMatchedRuleNames: List<String> = emptyList(),
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
                    stringResource(R.string.format_package_version, pluralStringResource(R.plurals.l10n_indicators, hashDatabaseCapability.indicatorCount, hashDatabaseCapability.indicatorCount), hashDatabaseCapability.version?.let { localizedNumber(it) } ?: "—")
                } else SecurityText.hashStatus(hashDatabaseCapability).resolve(LocalContext.current), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        val yaraCapability = BundledYaraEngine.capability
        Card(modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                Text(stringResource(R.string.ui_yara_title), style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold)
                Text(if (yaraCapability.active) pluralStringResource(R.plurals.l10n_rules, yaraCapability.ruleCount, yaraCapability.ruleCount)
                    else stringResource(R.string.ui_yara_disabled), style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary)
                Text(pluralStringResource(R.plurals.l10n_rule_matches, yaraMatchCount, yaraMatchCount),
                    style = MaterialTheme.typography.bodySmall)
                if (yaraMatchedRuleNames.isNotEmpty()) {
                    Text(yaraMatchedRuleNames.take(8).joinToString(", "),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        DetectionCoverage.layers.forEach { declared ->
            val layer = DetectionCoverage.status(declared.id) ?: declared
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
                    val copy = SecurityText.coverage.getValue(layer.id)
                    Text(stringResource(copy.first), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                    Text(statusText, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    val reason = when (layer.id) {
                        "signed-multi-hash-database" -> SecurityText.hashStatus(hashDatabaseCapability).resolve(LocalContext.current)
                        "yara-dex-and-assets" -> stringResource(if (yaraCapability.active) R.string.coverage_rules_body else R.string.coverage_rules_unavailable)
                        else -> stringResource(copy.second)
                    }
                    Text(reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        OutlinedButton(onClick = onImportYaraRulesForReview, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.detection_capabilities_import_yara))
        }
    }
}

