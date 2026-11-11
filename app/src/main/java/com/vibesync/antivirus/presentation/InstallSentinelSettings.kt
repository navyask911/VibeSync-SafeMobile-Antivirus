package com.vibesync.antivirus.presentation

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.style.TextOverflow
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.observer.InstallSentinelService
import com.vibesync.antivirus.ui.components.GlassCard

@Composable
internal fun InstallSentinelSettings(
    isRunningOverride: Boolean? = null,
    isEnabledOverride: Boolean? = null,
    onToggleOverride: ((Boolean) -> Unit)? = null
) {
    val context = LocalContext.current
    val serviceRunning by InstallSentinelService.running.collectAsStateWithLifecycle()
    val running = isRunningOverride ?: serviceRunning
    var desired by remember(context, isEnabledOverride) {
        mutableStateOf(isEnabledOverride ?: InstallSentinelService.enabled(context))
    }
    GlassCard(Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(stringResource(R.string.install_sentinel_title), style = MaterialTheme.typography.titleMedium,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(stringResource(if (running) R.string.install_sentinel_active else R.string.monitor_inactive),
                        style = MaterialTheme.typography.bodySmall,
                        color = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Switch(
                    modifier = Modifier.testTag("settings.install-sentinel"),
                    checked = running && desired,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = MaterialTheme.colorScheme.surface,
                        checkedTrackColor = MaterialTheme.colorScheme.primary,
                        uncheckedThumbColor = MaterialTheme.colorScheme.onSurfaceVariant,
                        uncheckedTrackColor = MaterialTheme.colorScheme.surfaceVariant,
                        uncheckedBorderColor = MaterialTheme.colorScheme.outline
                    ),
                    onCheckedChange = { enabled ->
                    desired = enabled
                    if (onToggleOverride != null) {
                        onToggleOverride.invoke(enabled)
                    } else if (enabled) {
                        context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE).edit()
                            .putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, true).apply()
                        InstallSentinelService.startFromVisibleUi(context)
                    } else InstallSentinelService.stop(context)
                })
            }
            Text(stringResource(R.string.install_sentinel_description),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}
