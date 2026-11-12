package com.vibesync.antivirus.presentation

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.WorkspacePremium
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.billing.SafeMobileBillingManager
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Currency
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

/**
 * Subscription paywall. Core offline protection remains free and experimental ML
 * is not marketed as production threat detection.
 */
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
    var selectedYears by rememberSaveable { mutableIntStateOf(1) }
    val manager = remember(context) { SafeMobileBillingManager(context) }
    val state by manager.state.collectAsStateWithLifecycle()
    val owner = LocalLifecycleOwner.current
    val canLaunchPurchase = activity != null && !activity.isFinishing && !activity.isDestroyed
    val selectedUnitPrice = if (selectedYears == 1) state.playPriceMicros else state.legacyPriceMicros
    val selectedCurrency = if (selectedYears == 1) state.playCurrency else state.legacyCurrency
    val yearsDescription = stringResource(R.string.pro_years)
    val estimatedTotal = selectedUnitPrice?.let { micros ->
        runCatching {
            val formatter = NumberFormat.getCurrencyInstance(locale)
            if (!selectedCurrency.isNullOrBlank()) formatter.currency = Currency.getInstance(selectedCurrency)
            formatter.format((micros.toDouble() / 1_000_000.0) * selectedYears)
        }.getOrNull()
    }
    BackHandler(onBack = onBack)

    DisposableEffect(manager) {
        manager.start()
        onDispose { manager.close() }
    }
    LaunchedEffect(manager) { manager.refreshLocalStatus() }
    LaunchedEffect(state.proActive) { onProStatusChanged(state.proActive) }
    DisposableEffect(manager, owner) {
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
            Icon(
                Icons.Outlined.WorkspacePremium,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.width(8.dp))
            Text(
                stringResource(R.string.pro_title),
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f),
                maxLines = 2,
                softWrap = true,
                overflow = TextOverflow.Ellipsis
            )
            TextButton(onClick = onBack) { Text(stringResource(R.string.close)) }
        }
        Text(stringResource(R.string.pro_truthful_summary), style = MaterialTheme.typography.bodyMedium)
        Text(
            stringResource(
                if (selectedYears == 1) R.string.pro_subscription_offer
                else R.string.pro_prepaid_offer
            ),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary
        )

        Text(stringResource(R.string.pro_years), style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.SemiBold)
        Slider(
            value = selectedYears.toFloat(),
            onValueChange = { selectedYears = it.roundToInt().coerceIn(1, 10) },
            valueRange = 1f..10f,
            steps = 8,
            modifier = Modifier.fillMaxWidth().semantics {
                contentDescription = yearsDescription
            }
        )
        estimatedTotal?.let { total ->
            Text(
                stringResource(R.string.pro_price_preview, total, selectedYears),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.primary
            )
        } ?: Text(
            stringResource(R.string.pro_price_unavailable),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        if (selectedYears == 1) {
            state.playUnitPrice?.let { unitPrice ->
                Text(
                    stringResource(R.string.pro_auto_renewal_terms, unitPrice),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            Text(
                stringResource(R.string.pro_cart_quantity_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(R.string.pro_prepaid_terms),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                stringResource(R.string.pro_non_restorable_warning),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        }
        listOf(
            R.string.pro_feature_free,
            R.string.pro_feature_research,
            R.string.pro_feature_updates,
            R.string.pro_feature_adfree,
        ).forEach { textRes ->
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(Icons.Outlined.CheckCircle, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                Text(stringResource(textRes), style = MaterialTheme.typography.bodyMedium)
            }
        }

        HorizontalDivider()
        Button(
            onClick = {
                activity?.takeIf { !it.isFinishing && !it.isDestroyed }?.let { host ->
                    if (selectedYears == 1) manager.launchPurchase(host)
                    else manager.launchMultiYearPassPurchase(host)
                }
            },
            enabled = canLaunchPurchase && state.connected && selectedUnitPrice != null &&
                !state.processing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(if (selectedYears == 1) R.string.pro_subscribe_annual else R.string.pro_prepaid_checkout))
        }
        OutlinedButton(
            onClick = { manager.restoreProLicenseFromPlayStore() },
            enabled = !state.processing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.pro_restore_check))
        }
        if (state.proActive) {
            Text(
                stringResource(
                    R.string.pro_active_until,
                    DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(state.expiresAt))
                ),
                color = MaterialTheme.colorScheme.primary
            )
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
            SafeMobileBillingManager.Notice.SUCCESS -> R.string.pro_purchase_success
        }
        if (noticeText != null) {
            Text(stringResource(noticeText), style = MaterialTheme.typography.bodySmall)
        }
        HorizontalDivider()
        Text(
            stringResource(R.string.pro_network_notice),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Text(
            stringResource(R.string.pro_device_disclaimer),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

private fun Context.paywallActivity(): Activity? {
    var current: Context? = this
    val seen = java.util.Collections.newSetFromMap(
        java.util.IdentityHashMap<Context, Boolean>()
    )
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
