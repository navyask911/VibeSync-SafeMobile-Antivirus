package com.vibesync.antivirus.presentation

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.vibesync.antivirus.R

@Composable
internal fun DeviceAdminPermissionDisclosureDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.security_guard_admin_consent_title)) },
        text = { Text(stringResource(R.string.security_guard_admin_consent_body)) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.security_guard_consent_continue))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.security_guard_consent_cancel))
            }
        }
    )
}

@Composable
internal fun OverlayPermissionDisclosureDialog(
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.security_guard_overlay_consent_title)) },
        text = { Text(stringResource(R.string.security_guard_overlay_consent_body)) },
        confirmButton = {
            TextButton(onClick = onConfirm) {
                Text(stringResource(R.string.security_guard_consent_continue))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.security_guard_consent_cancel))
            }
        }
    )
}
