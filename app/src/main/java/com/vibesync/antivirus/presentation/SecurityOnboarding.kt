package com.vibesync.antivirus.presentation

import android.content.Context
import android.os.Build
import android.os.Environment
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R

internal object OnboardingPrefs {
    const val NAME = "safe_mobile_onboarding"
    const val COMPLETED = "completed"
    const val STEP = "step"
    const val SENTINEL_OPT_IN = "sentinel_opt_in"
    const val FIRST_SCAN_REQUESTED = "first_scan_requested"
}
internal fun hasSharedStorageAccess(context: Context): Boolean =
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        runCatching { Environment.isExternalStorageManager() }.getOrDefault(false)
    } else {
        context.checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) == android.content.pm.PackageManager.PERMISSION_GRANTED
    }
internal fun hasNotificationAccess(context: Context): Boolean =
    Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
        context.checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == android.content.pm.PackageManager.PERMISSION_GRANTED

@Composable
internal fun SecurityOnboardingScreen(
    step: Int, storageAccessGranted: Boolean, notificationsGranted: Boolean, sentinelOptIn: Boolean,
    onRequestStorage: () -> Unit, onContinueStorage: () -> Unit, onContinueInstalledApps: () -> Unit,
    onRequestNotifications: () -> Unit, onSkipNotifications: () -> Unit, onEnableSentinel: () -> Unit,
    onDisableSentinel: () -> Unit, onFinish: () -> Unit, onSkipSetup: () -> Unit
) {
    val page = step.coerceIn(0, 3)
    val title = when (page) {
        0 -> R.string.setup_storage_title
        1 -> R.string.setup_apps_title
        2 -> R.string.setup_notifications_title
        else -> R.string.setup_sentinel_title
    }
    val description = when (page) {
        0 -> R.string.setup_storage_body
        1 -> R.string.setup_apps_body
        2 -> R.string.setup_notifications_body
        else -> R.string.setup_sentinel_body
    }
    val icon = when (page) {
        0 -> Icons.Default.FolderOpen
        1 -> Icons.Default.Apps
        2 -> Icons.Default.Notifications
        else -> Icons.Default.Security
    }
    Column(
        modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.background)
            .padding(horizontal = 22.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(18.dp), horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(stringResource(R.string.setup_title), style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onSurface, modifier = Modifier.weight(1f))
            TextButton(onClick = onSkipSetup) { Text(stringResource(R.string.setup_skip)) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            repeat(4) { index ->
                Box(Modifier.size(if (index == page) 14.dp else 10.dp).clip(RoundedCornerShape(50))
                    .background(if (index <= page) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceVariant))
            }
        }
        Spacer(Modifier.height(4.dp))
        Box(Modifier.size(96.dp).clip(RoundedCornerShape(24.dp))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)), contentAlignment = Alignment.Center) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(44.dp))
        }
        Text(stringResource(title), style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Bold)
        Text(stringResource(description), style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (page == 0 || page == 2) {
            val granted = if (page == 0) storageAccessGranted else notificationsGranted
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(if (granted) R.string.setup_permission_granted else R.string.setup_permission_missing),
                    Modifier.padding(14.dp), style = MaterialTheme.typography.labelLarge,
                    color = if (granted) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary)
            }
        }
        if (page == 3) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
                shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth()) {
                Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text(stringResource(R.string.setup_sentinel_switch), fontWeight = FontWeight.SemiBold)
                        Text(stringResource(R.string.setup_sentinel_scope), style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = sentinelOptIn, onCheckedChange = { if (it) onEnableSentinel() else onDisableSentinel() })
                }
            }
        }
        Button(onClick = {
            when (page) {
                0 -> if (storageAccessGranted) onContinueStorage() else onRequestStorage()
                1 -> onContinueInstalledApps()
                2 -> if (notificationsGranted) onSkipNotifications() else onRequestNotifications()
                else -> onFinish()
            }
        }, modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp), shape = RoundedCornerShape(50)) {
            Text(when (page) {
                0 -> stringResource(if (storageAccessGranted) R.string.setup_continue else R.string.setup_allow_storage)
                1 -> stringResource(R.string.setup_continue)
                2 -> stringResource(if (notificationsGranted) R.string.setup_continue else R.string.setup_allow_notifications)
                else -> stringResource(R.string.setup_finish)
            })
        }
        if (page == 0 && !storageAccessGranted) {
            OutlinedButton(onClick = onContinueStorage, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.setup_continue_limited)) }
        } else if (page == 2 && !notificationsGranted) {
            TextButton(onClick = onSkipNotifications) { Text(stringResource(R.string.setup_notifications_not_now)) }
        }
        Spacer(Modifier.weight(1f, fill = false))
        LinearProgressIndicator(progress = (page + 1) / 4f, modifier = Modifier.fillMaxWidth())
        Text(stringResource(R.string.setup_step_progress, page + 1), style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
