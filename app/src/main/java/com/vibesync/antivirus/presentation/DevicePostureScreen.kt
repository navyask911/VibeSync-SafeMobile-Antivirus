package com.vibesync.antivirus.presentation

import androidx.compose.ui.res.pluralStringResource
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.animation.animateContentSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.posture.PostureAccess
import com.vibesync.antivirus.core.posture.PostureFinding
import com.vibesync.antivirus.core.posture.PostureGrantState
import com.vibesync.antivirus.core.posture.PostureSettingsLinks
import com.vibesync.antivirus.core.posture.PostureText
import com.vibesync.antivirus.ui.components.CyberCard
import java.text.DateFormat
import java.util.Date

private val PostureWarning = Color(0xFFFFD54F)

@Composable
fun DevicePostureDashboardCard(state: DevicePostureUiState, onOpen: () -> Unit) {
    val context = LocalContext.current
    val preferences = remember(context) {
        context.getSharedPreferences("safemobile_posture_ack_v116", Context.MODE_PRIVATE)
    }
    var reviewed by remember(preferences) {
        mutableStateOf(preferences.getStringSet("reviewed", emptySet()).orEmpty().toSet())
    }
    val report = state.report
    val observed = report?.findings.orEmpty().filter { it.highRisk && !it.stale }
        .map { it.access.name + ":" + it.packageName }.toSet()
    // Expire an acknowledged grant only when a fresh, successful audit confirms its absence.
    androidx.compose.runtime.LaunchedEffect(report?.checkedAt) {
        if (report != null && report.unavailable.isEmpty()) {
            val retained = reviewed.intersect(observed)
            if (retained != reviewed) {
                reviewed = retained
                preferences.edit().putStringSet("reviewed", retained).apply()
            }
        }
    }
    if ((observed - reviewed).isNotEmpty()) {
        CyberCard(Modifier.fillMaxWidth().clickable(onClick = {
            reviewed = reviewed + observed
            preferences.edit().putStringSet("reviewed", reviewed).apply()
            onOpen()
        }),
            colors = CardDefaults.cardColors(containerColor = PostureWarning),
            border = BorderStroke(1.dp, PostureWarning)) {
            Row(Modifier.padding(16.dp), horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = Color(0xFF161B25))
                Text(stringResource(R.string.posture_dashboard_warning), color = Color(0xFF161B25),
                    fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            }
        }
    }
    CyberCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(Icons.Default.Security, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text(stringResource(R.string.posture_title), style = MaterialTheme.typography.titleMedium)
            }
            Text(stringResource(when {
                state.refreshing -> R.string.posture_checking
                state.failed -> R.string.posture_failed
                state.report == null -> R.string.posture_not_checked
                state.report.unavailable.isNotEmpty() -> R.string.posture_unavailable
                else -> R.string.posture_risk_note
            }), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedButton(onClick = onOpen, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.posture_open))
            }
        }
    }
}

/** Only metadata is displayed. Every permission change is performed by the user in Android settings. */
@Composable
fun DevicePostureScreen(
    state: DevicePostureUiState,
    alertsAvailable: Boolean,
    onRefresh: () -> Unit,
    onMonitoringChanged: (Boolean) -> Unit,
    onEnableAlerts: () -> Unit
) {
    val context = LocalContext.current
    Column(Modifier.animateContentSize(), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text(stringResource(R.string.posture_title), style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.Bold)
        ExpandableText(stringResource(R.string.posture_intro), maxLines = 3)
        ExpandableText(stringResource(R.string.posture_risk_note), maxLines = 3)
        Button(onClick = onRefresh, enabled = !state.refreshing, modifier = Modifier.fillMaxWidth()) {
            if (state.refreshing) CircularProgressIndicator(Modifier.size(18.dp).padding(end = 4.dp), strokeWidth = 2.dp)
            Text(stringResource(if (state.refreshing) R.string.posture_checking else R.string.posture_refresh))
        }
        if (state.failed) Text(stringResource(R.string.posture_failed), color = PostureWarning)
        state.report?.let { report ->
            Text(stringResource(R.string.posture_checked_at, displayPostureTime(report.checkedAt)),
                style = MaterialTheme.typography.labelSmall)
            if (report.highRiskAppCount > 0) Text(pluralStringResource(R.plurals.l10n_posture_apps, report.highRiskAppCount, report.highRiskAppCount),
                color = PostureWarning, fontWeight = FontWeight.Bold)
        }
        CyberCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.posture_monitor_title), style = MaterialTheme.typography.titleMedium)
                ExpandableText(stringResource(R.string.posture_monitor_description), maxLines = 3)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.posture_monitor_toggle), modifier = Modifier.weight(1f))
                    Switch(checked = state.monitor?.enabled ?: true, onCheckedChange = onMonitoringChanged)
                }
                val monitor = state.monitor
                Text(if (monitor != null && monitor.lastCheckAt > 0)
                    stringResource(R.string.posture_monitor_last, displayPostureTime(monitor.lastCheckAt))
                    else stringResource(R.string.posture_monitor_waiting), style = MaterialTheme.typography.bodySmall)
                if (monitor?.storageError == true) Text(stringResource(R.string.posture_storage_error), color = PostureWarning)
                if (monitor?.partial == true) Text(stringResource(R.string.posture_monitor_partial), color = PostureWarning)
                if ((monitor?.pendingChanges ?: 0) > 0) Text(pluralStringResource(R.plurals.l10n_pending_changes, monitor!!.pendingChanges, monitor.pendingChanges),
                    style = MaterialTheme.typography.bodySmall)
                if (!alertsAvailable) {
                    Text(stringResource(R.string.posture_alerts_off), style = MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick = onEnableAlerts, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.posture_enable_alerts))
                    }
                }
            }
        }
        PostureAccess.entries.forEach { access ->
            CyberCard(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(stringResource(PostureText.title(access)), style = MaterialTheme.typography.titleMedium)
                    if (access == PostureAccess.OVERLAY) ExpandableText(stringResource(R.string.posture_overlay_limit), maxLines = 3)
                    val report = state.report
                    if (report == null) Text(stringResource(R.string.posture_not_checked), style = MaterialTheme.typography.bodySmall)
                    else {
                        if (access in report.unavailable) Text(stringResource(R.string.posture_unavailable), color = PostureWarning,
                            style = MaterialTheme.typography.bodySmall)
                        val findings = report.findings.filter { it.access == access }
                            .sortedWith(compareByDescending<PostureFinding> { it.highRisk }.thenBy { it.appName.lowercase() })
                        if (findings.isEmpty() && access !in report.unavailable) Text(stringResource(R.string.posture_no_access),
                            style = MaterialTheme.typography.bodySmall)
                        findings.forEachIndexed { index, finding ->
                            if (index > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            PostureFindingRow(finding) {
                                if (!PostureSettingsLinks.open(context, finding))
                                    Toast.makeText(context, R.string.posture_settings_missing, Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PostureFindingRow(finding: PostureFinding, onFix: () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
        Text(finding.appName, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        Text(finding.componentName ?: finding.packageName, style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (finding.highRisk) Text(stringResource(R.string.posture_high_risk), color = PostureWarning,
            style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold)
        if (finding.systemApp != false) Text(stringResource(if (finding.systemApp == true) R.string.posture_system
            else R.string.posture_unknown_system), style = MaterialTheme.typography.labelSmall)
        Text(stringResource(when (finding.state) {
            PostureGrantState.ENABLED -> R.string.posture_enabled
            PostureGrantState.NOT_GRANTED -> R.string.posture_not_granted
            PostureGrantState.UNKNOWN -> R.string.posture_unknown_grant
        }), style = MaterialTheme.typography.bodySmall)
        if (finding.stale) Text(stringResource(R.string.posture_stale), color = PostureWarning,
            style = MaterialTheme.typography.bodySmall)
        ExpandableText(stringResource(PostureText.explanation(finding)), maxLines = 3)
        if (finding.access != PostureAccess.OVERLAY || (finding.state == PostureGrantState.ENABLED && !finding.stale)) {
            OutlinedButton(onClick = onFix) { Text(stringResource(R.string.posture_fix)) }
        }
    }
}

@Composable
private fun displayPostureTime(timestamp: Long): String = localizedDate(timestamp)
