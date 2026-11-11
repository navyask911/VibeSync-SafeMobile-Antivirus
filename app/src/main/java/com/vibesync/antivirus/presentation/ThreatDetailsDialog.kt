package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.observer.NotificationDeepLink

@Composable
internal fun ThreatDetailsDialog(
    item: NotificationDeepLink,
    onScan: () -> Unit,
    onDelete: () -> Unit,
    onWhitelist: () -> Unit,
    onDismiss: () -> Unit
) {
    val fileName = item.fileName?.takeIf(String::isNotBlank)
        ?: item.fileUri?.substringAfterLast('/')?.takeIf(String::isNotBlank)
        ?: item.packageName
        ?: stringResource(R.string.unknown_file)
    val path = item.filePath?.takeIf(String::isNotBlank) ?: item.fileUri
        ?: item.packageName?.let { "package:$it" }
        ?: stringResource(R.string.notification_details_scan_unavailable)
    val reason = item.reason?.takeIf(String::isNotBlank)
        ?: item.notificationType
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.notification_details_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                DetailField(stringResource(R.string.notification_details_filename), fileName)
                DetailField(stringResource(R.string.notification_details_path), path)
                DetailField(stringResource(R.string.notification_details_reason), reason)
                item.logId?.let { DetailField(stringResource(R.string.notification_details_log_id), it) }
            }
        },
        confirmButton = {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                TextButton(onClick = onWhitelist) {
                    Text(stringResource(R.string.notification_details_whitelist))
                }
                TextButton(onClick = onDelete) {
                    Text(stringResource(R.string.notification_details_delete))
                }
                TextButton(onClick = onScan) {
                    Text(stringResource(R.string.notification_details_scan))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.notification_details_close))
            }
        }
    )
}

@Composable
private fun DetailField(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
    }
}
