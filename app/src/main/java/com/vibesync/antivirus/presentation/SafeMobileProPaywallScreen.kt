package com.vibesync.antivirus.presentation

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.WorkspacePremium
import androidx.compose.material3.*
import androidx.compose.runtime.*
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
import java.util.Date

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
    val locale = LocalConfiguration.current.locales[0]
    val manager = remember(context) { SafeMobileBillingManager(context) }
    val state by manager.state.collectAsStateWithLifecycle()
    val owner = LocalLifecycleOwner.current
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
                Icons.Default.WorkspacePremium,
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
            stringResource(R.string.pro_subscription_offer),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary
        )
        listOf(
            R.string.pro_feature_free,
            R.string.pro_feature_research,
            R.string.pro_feature_updates,
            R.string.pro_feature_adfree,
        ).forEach { textRes ->
            Text("✓  " + stringResource(textRes), style = MaterialTheme.typography.bodyMedium)
        }

        HorizontalDivider()
        Button(
            onClick = { activity?.let { manager.launchPurchase(it) } },
            enabled = activity != null && state.connected && state.playPriceMicros != null &&
                !state.processing,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(stringResource(R.string.pro_unlock))
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

private tailrec fun Context.paywallActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.paywallActivity()
    else -> null
}
