package com.vibesync.antivirus.presentation

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.text.style.TextOverflow

/** Confirmation-only UI; caller dismisses before starting its asynchronous delete operation. */
@Composable
internal fun QuarantineDeleteDialog(
    fileName: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit
) {
    AlertDialog(
        properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.quarantine_delete_confirm_title)) },
        text = {
            Text(
                stringResource(R.string.quarantine_delete_confirm_body) + "\n\n" + fileName,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis
            )
        },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.quarantine_delete), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.close)) }
        }
    )
}
