package com.vibesync.antivirus.presentation

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.WorkspacePremium
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.billing.SafeMobileBillingManager
import java.text.DateFormat
import java.util.Date
import java.util.Locale

private const val BILLING_UNAVAILABLE_MESSAGE =
    "Billing is currently unavailable. Please ensure you are using the Play Store version."

/** SafeMobile Pro prepaid plan. Google Play prepaid periods are limited to one year. */
@Composable
fun SafeMobileProPaywallScreen(
    onBack: () -> Unit,
    onProStatusChanged: (Boolean) -> Unit = {}
) {
    val context = LocalContext.current
    val activity = remember(context) { context.paywallActivity() }
    val locale = LocalConfiguration.current.locales.let { locales ->
        if (locales.size() == 0) Locale.getDefault() else locales[0]
    }
    // Use a safe cast so an unexpected application context cannot crash the paywall.
    val manager = remember(context.applicationContext) {
        (context.applicationContext as? SafeMobileApp)?.proBillingManager
    }

    BackHandler(onBack = onBack)

    if (manager == null) {
        LaunchedEffect(context) {
            Toast.makeText(context, BILLING_UNAVAILABLE_MESSAGE, Toast.LENGTH_LONG).show()
        }
        Column(
            modifier = Modifier.fillMaxWidth().padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(stringResource(R.string.pro_title), style = MaterialTheme.typography.headlineSmall)
            Text(BILLING_UNAVAILABLE_MESSAGE, color = MaterialTheme.colorScheme.error)
            TextButton(onClick = onBack) { Text(stringResource(R.string.close)) }
        }
        return
    }

    val state by manager.state.collectAsStateWithLifecycle()
    val canLaunchPurchase = activity != null && !activity.isFinishing && !activity.isDestroyed

    LaunchedEffect(manager) {
        manager.start()
        manager.refreshLocalStatus()
    }
    LaunchedEffect(state.proActive) { onProStatusChanged(state.proActive) }
    LaunchedEffect(state.notice) {
        if (state.notice == SafeMobileBillingManager.Notice.UNAVAILABLE) {
            Toast.makeText(context, BILLING_UNAVAILABLE_MESSAGE, Toast.LENGTH_LONG).show()
        }
    }
    DisposableEffect(manager, LocalLifecycleOwner.current) {
        val owner = LocalLifecycleOwner.current
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) manager.start()
        }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer) }
    }

    Column(
        modifier = Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Outlined.WorkspacePremium, contentDescription = null,
                tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.pro_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f),
                maxLines = 2, softWrap = true, overflow = TextOverflow.Ellipsis)
            TextButton(onClick = onBack) { Text(stringResource(R.string.close)) }
        }
        Text(stringResource(R.string.pro_truthful_summary), style = MaterialTheme.typography.bodyMedium)
        Text(stringResource(R.string.pro_prepaid_offer), style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary)
        state.playUnitPrice?.let { price ->
            Text(stringResource(R.string.pro_one_year_price, price),
                style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
        } ?: Text(stringResource(R.string.pro_price_unavailable),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(R.string.pro_prepaid_duration_limit),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(R.string.pro_device_binding_explanation),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

        listOf(R.string.pro_feature_free, R.string.pro_feature_research,
            R.string.pro_feature_updates, R.string.pro_feature_adfree).forEach { textRes ->
            Row(verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.CheckCircle, contentDescription = null,
                    tint = MaterialTheme.colorScheme.secondary)
                Text(stringResource(textRes), style = MaterialTheme.typography.bodyMedium)
            }
        }

        HorizontalDivider()
        Button(
            onClick = {
                val currentActivity = activity
                if (currentActivity == null || currentActivity.isFinishing || currentActivity.isDestroyed) {
                    Toast.makeText(context, BILLING_UNAVAILABLE_MESSAGE, Toast.LENGTH_LONG).show()
                } else {
                    try {
                        manager.launchPurchase(currentActivity)
                    } catch (_: Exception) {
                        Toast.makeText(context, BILLING_UNAVAILABLE_MESSAGE, Toast.LENGTH_LONG).show()
                    }
                }
            },
            enabled = canLaunchPurchase && state.connected && state.deviceIdAvailable &&
                state.playPriceMicros != null && !state.processing,
            modifier = Modifier.fillMaxWidth()
        ) { Text(stringResource(R.string.pro_buy_or_extend_one_year)) }
        OutlinedButton(
            onClick = {
                try {
                    manager.restoreProLicenseFromPlayStore()
                } catch (_: Exception) {
                    Toast.makeText(context, BILLING_UNAVAILABLE_MESSAGE, Toast.LENGTH_LONG).show()
                }
            },
            enabled = !state.processing, modifier = Modifier.fillMaxWidth()
        ) { Text(stringResource(R.string.pro_restore_check)) }

        if (state.proActive) {
            Text(stringResource(R.string.pro_active_until,
                DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(state.expiresAt))),
                color = MaterialTheme.colorScheme.primary)
        } else {
            Text(stringResource(R.string.pro_not_active))
        }
        val noticeText = when (state.notice) {
            SafeMobileBillingManager.Notice.NONE -> null
            SafeMobileBillingManager.Notice.UNAVAILABLE -> R.string.pro_purchase_unavailable
            SafeMobileBillingManager.Notice.CANCELED -> R.string.pro_purchase_canceled
            SafeMobileBillingManager.Notice.PENDING -> R.string.pro_purchase_pending
            SafeMobileBillingManager.Notice.RECHECK -> R.string.pro_purchase_recheck
            SafeMobileBillingManager.Notice.DEVICE_STORAGE_ERROR -> R.string.pro_storage_failed
            SafeMobileBillingManager.Notice.DEVICE_MISMATCH -> R.string.pro_device_mismatch
            SafeMobileBillingManager.Notice.DEVICE_BINDING_UNAVAILABLE -> R.string.pro_device_binding_unavailable
            SafeMobileBillingManager.Notice.SUCCESS -> R.string.pro_purchase_success
        }
        if (noticeText != null) {
            val bindingError = state.notice == SafeMobileBillingManager.Notice.DEVICE_MISMATCH ||
                state.notice == SafeMobileBillingManager.Notice.DEVICE_BINDING_UNAVAILABLE
            Text(stringResource(noticeText), style = MaterialTheme.typography.bodySmall,
                color = if (bindingError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
        }
        if (!state.deviceIdAvailable) {
            Text(stringResource(R.string.pro_device_binding_unavailable),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        }
        HorizontalDivider()
        Text(stringResource(R.string.pro_network_notice),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(stringResource(R.string.pro_device_disclaimer),
            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun Context.paywallActivity(): Activity? {
    var current: Context? = this
    val seen = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Context, Boolean>())
    while (current != null && seen.add(current)) {
        when (current) {
            is Activity -> return current
            is ContextWrapper -> {
                val next = current.baseContext
                if (next === current) return null
                current = next
            }
            else -> return null
        }
    }
    return null
}
