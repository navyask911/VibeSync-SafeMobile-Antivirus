package com.vibesync.antivirus.presentation

import android.content.ActivityNotFoundException
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.security.DeviceAdminManager
import com.vibesync.antivirus.ui.components.GlassCard

@Composable
internal fun DeviceAdminCard(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val manager = remember(context) { DeviceAdminManager(context) }
    var active by remember(context) { mutableStateOf(manager.isActive()) }
    var statusMessage by remember { mutableStateOf<Int?>(null) }

    DisposableEffect(lifecycleOwner, manager) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) active = manager.isActive()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    GlassCard(modifier = modifier.fillMaxWidth()) {
        Text(stringResource(R.string.device_admin_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(
            stringResource(if (active) R.string.device_admin_status_active else R.string.device_admin_status_inactive),
            style = MaterialTheme.typography.labelLarge,
            color = if (active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary
        )
        Text(stringResource(R.string.device_admin_body), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            if (!active) {
                PrimaryActionButton(
                    text = stringResource(R.string.device_admin_enable),
                    onClick = {
                        try {
                            context.startActivity(manager.enableIntent())
                        } catch (_: ActivityNotFoundException) {
                            statusMessage = R.string.device_admin_activity_unavailable
                        } catch (_: SecurityException) {
                            statusMessage = R.string.device_admin_activity_unavailable
                        }
                    }
                )
            } else {
                OutlinedButton(
                    onClick = {
                        statusMessage = if (manager.applyMinimumPasswordLength()) R.string.device_admin_password_applied
                        else R.string.device_admin_password_failed
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.device_admin_apply_password)) }
                OutlinedButton(
                    onClick = {
                        val locked = manager.forceLock()
                        if (!locked) statusMessage = R.string.device_admin_lock_unavailable
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text(stringResource(R.string.device_admin_lock_now)) }
            }
            statusMessage?.let {
                Text(stringResource(it), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
