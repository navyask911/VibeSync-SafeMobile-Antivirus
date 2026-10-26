package com.vibesync.antivirus.presentation

import android.content.Context
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material3.*
import com.vibesync.antivirus.ui.components.CyberCard as Card
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import com.vibesync.antivirus.ui.components.GlassCard

@Composable
internal fun LimitedProtectionBanner(downloads: Boolean, whatsapp: Boolean, running: Boolean, onSetup: () -> Unit) {
    if (downloads && whatsapp && running) return
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFFFD54F)), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.ui_sentinel_limited), color = Color(0xFF211A00), style = MaterialTheme.typography.titleMedium)
            Text(when {
                !running || (!downloads && !whatsapp) -> stringResource(R.string.ui_sentinel_both_off)
                !downloads -> stringResource(R.string.ui_sentinel_download_off)
                else -> stringResource(R.string.ui_sentinel_whatsapp_off)
            }, color = Color(0xFF211A00))
            TextButton(onClick = onSetup) { Text(stringResource(R.string.ui_sentinel_setup), color = Color(0xFF211A00)) }
        }
    }
}

@Composable
internal fun SentinelFolderPanel(context: Context, folders: List<Uri>, running: Boolean,
    onAdd: (String) -> Unit, onRemove: (Uri) -> Unit, onStart: () -> Unit, onStop: () -> Unit, onSkip: () -> Unit) {
    GlassCard(Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text(stringResource(R.string.ui_sentinel_setup_title), style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.tertiary)
            Text(stringResource(R.string.ui_sentinel_intro))
            Text(stringResource(R.string.ui_sentinel_scoped))
            Text(stringResource(R.string.ui_sentinel_select_tip),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text((if (running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.DOWNLOADS)) "✓ " else "○ ") + stringResource(R.string.ui_sentinel_download_folder))
            Button(onClick = { onAdd(StorageAccessPreferences.DOWNLOADS) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.ui_sentinel_enable_download)) }
            Text((if (running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.WHATSAPP)) "✓ " else "○ ") + stringResource(R.string.ui_sentinel_whatsapp_folder))
            Button(onClick = { onAdd(StorageAccessPreferences.WHATSAPP) }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.ui_sentinel_enable_whatsapp)) }
            folders.forEach { uri ->
                Row(Modifier.fillMaxWidth()) {
                    Text(StorageAccessPreferences.displayName(uri), modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    IconButton(onClick = { onRemove(uri) }) { Icon(Icons.Default.DeleteOutline, contentDescription = stringResource(R.string.ui_sentinel_remove_folder)) }
                }
            }
            Text(if (running) stringResource(R.string.ui_sentinel_running) else stringResource(R.string.ui_sentinel_stopped), style = MaterialTheme.typography.labelLarge)
            if (running) OutlinedButton(onClick = onStop, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.ui_sentinel_stop)) }
            else if (folders.isNotEmpty()) OutlinedButton(onClick = onStart, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.ui_sentinel_start)) }
            Text(stringResource(R.string.ui_sentinel_best_effort), style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = onSkip, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.ui_sentinel_continue)) }
            TextButton(onClick = onSkip, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.setup_skip)) }
        }
    }
}
