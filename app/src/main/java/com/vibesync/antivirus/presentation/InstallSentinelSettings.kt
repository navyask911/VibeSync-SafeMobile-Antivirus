package com.vibesync.antivirus.presentation

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.observer.InstallSentinelService
import com.vibesync.antivirus.ui.components.GlassCard

@Composable
internal fun InstallSentinelSettings() {
    val context = LocalContext.current
    val running by InstallSentinelService.running.collectAsStateWithLifecycle()
    var desired by remember { mutableStateOf(InstallSentinelService.enabled(context)) }
    GlassCard(Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.install_sentinel_title), Modifier.weight(1f), style = MaterialTheme.typography.titleMedium)
                Switch(checked = running && desired, onCheckedChange = { enabled ->
                    desired = enabled
                    if (enabled) {
                        context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE).edit()
                            .putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, true).apply()
                        InstallSentinelService.startFromVisibleUi(context)
                    } else InstallSentinelService.stop(context)
                })
            }
            Text(stringResource(if (running) R.string.install_sentinel_active else R.string.monitor_inactive),
                color = if (running) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
            Text(stringResource(R.string.install_sentinel_description), style = MaterialTheme.typography.bodySmall)
        }
    }
}
