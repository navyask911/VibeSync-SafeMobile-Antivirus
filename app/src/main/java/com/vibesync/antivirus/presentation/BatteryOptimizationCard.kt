package com.vibesync.antivirus.presentation

import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ui.components.CyberCard

/** User-consented system-settings advisory; do not assume OEM power policy can be bypassed. */
@Composable
internal fun BatteryOptimizationCard(resumeEpoch: Int = 0) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val powerManager = remember(context) { context.getSystemService(PowerManager::class.java) }
    fun shouldShow() = powerManager?.let {
        // Battery saver is separate from the per-app exemption; do not leave a false red card.
        !it.isIgnoringBatteryOptimizations(context.packageName)
    } ?: false
    var needsAttention by remember(context) { mutableStateOf(shouldShow()) }
    DisposableEffect(context, lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) needsAttention = shouldShow()
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(resumeEpoch) { needsAttention = shouldShow() }
    if (!needsAttention) return
    CyberCard(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
            Text(stringResource(R.string.battery_review_title), color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.battery_review_body), color = MaterialTheme.colorScheme.onErrorContainer,
                style = MaterialTheme.typography.bodySmall)
            OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = {
                // Only request exemption after an explicit user action. Android owns consent;
                // an exemption does not bypass force-stop, OEM policies or battery saver.
                val request = if (powerManager?.isIgnoringBatteryOptimizations(context.packageName) == false) {
                    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:" + context.packageName))
                } else {
                    Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                }
                runCatching { context.startActivity(request) }.recoverCatching {
                    // Some OEMs do not expose the per-app request activity.
                    context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                }.onFailure {
                    Toast.makeText(context, R.string.battery_review_unavailable, Toast.LENGTH_LONG).show()
                }
            }) { Text(stringResource(R.string.battery_review_action)) }
        }
    }
}
