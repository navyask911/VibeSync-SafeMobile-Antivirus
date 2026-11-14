package com.vibesync.antivirus.presentation

import android.content.Context
import android.net.Uri
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.RadioButtonUnchecked
import androidx.compose.material3.*
import com.vibesync.antivirus.ui.components.CyberCard as Card
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import com.vibesync.antivirus.ui.components.GlassCard

@Composable
internal fun LimitedProtectionBanner(downloads: Boolean, whatsapp: Boolean, running: Boolean, onSetup: () -> Unit) {
    if (downloads && whatsapp && running) return
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFFFFD54F)), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.Warning, contentDescription = null, tint = Color(0xFF211A00))
                Text(stringResource(R.string.ui_sentinel_limited), color = Color(0xFF211A00), style = MaterialTheme.typography.titleMedium)
            }
            Text(when {
                !running || (!downloads && !whatsapp) -> stringResource(R.string.ui_sentinel_both_off)
                !downloads -> stringResource(R.string.ui_sentinel_download_off)
                else -> stringResource(R.string.ui_sentinel_whatsapp_off)
            }, color = Color(0xFF211A00), maxLines = 3, overflow = TextOverflow.Ellipsis)
            TextButton(onClick = onSetup, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.ui_sentinel_setup), color = Color(0xFF211A00)) }
        }
    }
}

@Composable
internal fun SentinelFolderPanel(
    context: Context,
    folders: List<Uri>,
    running: Boolean,
    customFolders: List<Uri>,
    onAdd: (String) -> Unit,
    onAddCustom: () -> Unit,
    onRemove: (Uri) -> Unit,
    onStart: () -> Unit,
    onStop: () -> Unit
) {
    val customCount = customFolders.size
    GlassCard(Modifier.fillMaxWidth()) {
        Column(Modifier.animateContentSize(), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.ui_sentinel_setup_title), style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.tertiary)
            ExpandableText(stringResource(R.string.ui_sentinel_intro), maxLines = 3)
            ExpandableText(stringResource(R.string.ui_sentinel_scoped), maxLines = 3)
            ExpandableText(stringResource(R.string.ui_sentinel_select_tip), maxLines = 3)
            val downloadsActive = running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.DOWNLOADS)
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(if (downloadsActive) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
                    contentDescription = null, tint = if (downloadsActive) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.ui_sentinel_download_folder))
            }
            Button(onClick = { onAdd(StorageAccessPreferences.DOWNLOADS) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.ui_sentinel_enable_download)) }
            val whatsappActive = running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.WHATSAPP)
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(if (whatsappActive) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
                    contentDescription = null, tint = if (whatsappActive) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.ui_sentinel_whatsapp_folder))
            }
            Button(onClick = { onAdd(StorageAccessPreferences.WHATSAPP) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.ui_sentinel_enable_whatsapp)) }
            val telegramActive = running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.TELEGRAM)
            Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(if (telegramActive) Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
                    contentDescription = null, tint = if (telegramActive) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.onSurfaceVariant)
                Text(stringResource(R.string.ui_sentinel_telegram_folder))
            }
            Button(onClick = { onAdd(StorageAccessPreferences.TELEGRAM) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.ui_sentinel_enable_telegram)) }
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Text(stringResource(R.string.ui_sentinel_custom_folders), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.ui_sentinel_folder_limit), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(
                modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                customFolders.forEach { uri ->
                    InputChip(
                        selected = false,
                        onClick = { onRemove(uri) },
                        label = { Text(StorageAccessPreferences.displayName(uri), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                        trailingIcon = { Icon(Icons.Outlined.Close, contentDescription = stringResource(R.string.ui_sentinel_remove_folder)) },
                        modifier = Modifier.heightIn(min = 48.dp)
                    )
                }
            }
            Button(
                onClick = onAddCustom,
                enabled = customCount < StorageAccessPreferences.MAX_CUSTOM_FOLDERS,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp)
            ) { Text(stringResource(R.string.ui_sentinel_add_custom_folder)) }
            Text(stringResource(R.string.ui_sentinel_running).takeIf { running } ?: stringResource(R.string.ui_sentinel_stopped),
                style = MaterialTheme.typography.labelLarge)
            if (running) OutlinedButton(onClick = onStop, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.ui_sentinel_stop)) }
            else if (folders.isNotEmpty()) OutlinedButton(onClick = onStart, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.ui_sentinel_start)) }
            ExpandableText(stringResource(R.string.ui_sentinel_best_effort), maxLines = 3)
        }
    }
}
