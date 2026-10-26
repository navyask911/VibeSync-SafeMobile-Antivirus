package com.vibesync.antivirus.presentation

import android.content.Context
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
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
            Text("⚠ Limited Protection Active", color = Color(0xFF211A00), style = MaterialTheme.typography.titleMedium)
            Text(when {
                !running || (!downloads && !whatsapp) -> "Download and WhatsApp folders are not being monitored."
                !downloads -> "The Download folder is not being monitored."
                else -> "The WhatsApp Documents folder is not being monitored."
            }, color = Color(0xFF211A00))
            TextButton(onClick = onSetup) { Text("Set up folder monitoring", color = Color(0xFF211A00)) }
        }
    }
}

@Composable
internal fun SentinelFolderPanel(context: Context, folders: List<Uri>, running: Boolean,
    onAdd: (String) -> Unit, onRemove: (Uri) -> Unit, onStart: () -> Unit, onStop: () -> Unit, onSkip: () -> Unit) {
    GlassCard(Modifier.fillMaxWidth()) {
        Column(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Critical Protection Required", style = MaterialTheme.typography.headlineSmall, color = MaterialTheme.colorScheme.tertiary)
            Text("Scammers use WhatsApp to send fake APKs. SafeMobile needs access to scan these before you install them.")
            Text("Due to Android 11+ Scoped Storage, SafeMobile can only monitor the specific folders you select. Please select your Download folder where Android allows it.")
            Text("Android 11+ blocks the main Download folder and storage root in its picker. Choose a Download subfolder for browser downloads, or scan individual files. WhatsApp Documents is often under Android/media/com.whatsapp/WhatsApp/Media. Any other folder you select is saved and monitored too.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text((if (running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.DOWNLOADS)) "✓ " else "○ ") + "Download Folder (browser downloads)")
            Button(onClick = { onAdd(StorageAccessPreferences.DOWNLOADS) }, modifier = Modifier.fillMaxWidth()) { Text("Enable Download Monitoring") }
            Text((if (running && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.WHATSAPP)) "✓ " else "○ ") + "WhatsApp Documents Folder (APKs sent via chat)")
            Button(onClick = { onAdd(StorageAccessPreferences.WHATSAPP) }, modifier = Modifier.fillMaxWidth()) { Text("Enable WhatsApp Monitoring") }
            folders.forEach { uri ->
                Row(Modifier.fillMaxWidth()) {
                    Text(StorageAccessPreferences.displayName(uri), modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                    IconButton(onClick = { onRemove(uri) }) { Icon(Icons.Default.DeleteOutline, contentDescription = "Remove monitored folder") }
                }
            }
            Text(if (running) "Monitoring granted folders recursively" else "Folder monitoring is stopped", style = MaterialTheme.typography.labelLarge)
            if (running) OutlinedButton(onClick = onStop, modifier = Modifier.fillMaxWidth()) { Text("Stop monitoring") }
            else if (folders.isNotEmpty()) OutlinedButton(onClick = onStart, modifier = Modifier.fillMaxWidth()) { Text("Start monitoring saved folders") }
            Text("Monitoring is best-effort; Android can stop background work. Only accessible, granted folders are checked.", style = MaterialTheme.typography.bodySmall)
            OutlinedButton(onClick = onSkip, modifier = Modifier.fillMaxWidth()) { Text("Continue with Limited Protection") }
            TextButton(onClick = onSkip, modifier = Modifier.fillMaxWidth()) { Text("Skip") }
        }
    }
}
