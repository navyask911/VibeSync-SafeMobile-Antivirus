package com.vibesync.antivirus.core.billing

import android.app.Activity
import android.content.Context
import com.android.billingclient.api.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest

/**
 * Device-bound, non-renewing Google Play prepaid subscription.
 * The Play base plan is one year; buying it again tops up another year.
 */
class SafeMobileBillingManager(context: Context) : PurchasesUpdatedListener {
    private val app = context.applicationContext
    private val ledger = ProEntitlementStore(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow(
        BillingUiState(deviceIdAvailable = DeviceUtils.fingerprint(app) != null)
    )
    val state: StateFlow<BillingUiState> = _state.asStateFlow()
    private var closed = false
    private var connecting = false

    private val billingClient = BillingClient.newBuilder(app)
        .setListener(this)
        .enablePendingPurchases(
            PendingPurchasesParams.newBuilder()
                .enableOneTimeProducts()
                .enablePrepaidPlans()
                .build()
        )
        .enableAutoServiceReconnection()
        .build()

    data class BillingUiState(
        val connected: Boolean = false,
        val processing: Boolean = false,
        val proActive: Boolean = false,
        val expiresAt: Long = 0L,
        val deviceIdAvailable: Boolean = false,
        val playUnitPrice: String? = null,
        val playPriceMicros: Long? = null,
        val playCurrency: String? = null,
        val notice: Notice = Notice.NONE,
    )

    enum class Notice {
        NONE, UNAVAILABLE, CANCELED, PENDING, RECHECK, DEVICE_STORAGE_ERROR,
        DEVICE_MISMATCH, DEVICE_BINDING_UNAVAILABLE, SUCCESS
    }

    fun checkProStatusForThisDevice(): Boolean = ledger.checkProStatusForThisDevice()

    fun refreshLocalStatus() {
        scope.launch {
            val expiry = withContext(Dispatchers.IO) { ledger.expiresAt() }
            _state.value = _state.value.copy(
                proActive = expiry > System.currentTimeMillis(),
                expiresAt = expiry,
                deviceIdAvailable = DeviceUtils.fingerprint(app) != null
            )
        }
    }

    /** Called from Application on process launch and when the paywall resumes. */
    fun start() {
        if (closed || connecting) return
        refreshLocalStatus()
        if (billingClient.isReady) {
            _state.value = _state.value.copy(connected = true)
            queryPrepaidPlan()
            recoverPurchases()
            return
        }
        connecting = true
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingServiceDisconnected() {
                if (closed) return
                connecting = false
                _state.value = _state.value.copy(
                    connected = false, processing = false, notice = Notice.UNAVAILABLE
                )
            }

            override fun onBillingSetupFinished(result: BillingResult) {
                if (closed) return
                connecting = false
                if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                    _state.value = _state.value.copy(connected = false, notice = Notice.UNAVAILABLE)
                    return
                }
                _state.value = _state.value.copy(connected = true)
                queryPrepaidPlan()
                recoverPurchases()
            }
        })
    }

    /** Restore active prepaid purchases from Play every time the app starts. */
    private fun recoverPurchases() {
        if (closed || !billingClient.isReady) return
        billingClient.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder()
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
        ) { result, purchases ->
            if (closed) return@queryPurchasesAsync
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                val active = purchases.filter { PRODUCT_ID in it.products }
                if (active.isNotEmpty()) active.forEach(::processPrepaidPurchase)
                else refreshLocalStatus()
            } else {
                _state.value = _state.value.copy(notice = Notice.UNAVAILABLE)
            }
        }
    }

    private data class PrepaidPlan(
        val details: ProductDetails,
        val offer: ProductDetails.SubscriptionOfferDetails,
        val phase: ProductDetails.PricingPhase
    )

    /**
     * Accept only the configured one-year, non-recurring prepaid base plan.
     * Auto-renewing plans and other base-plan IDs are not used as fallbacks.
     */
    private fun queryPrepaidPlan(callback: ((PrepaidPlan?) -> Unit)? = null) {
        if (!billingClient.isReady || closed) {
            callback?.invoke(null)
            return
        }
        val product = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(PRODUCT_ID)
            .setProductType(BillingClient.ProductType.SUBS)
            .build()
        billingClient.queryProductDetailsAsync(
            QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()
        ) { result, products ->
            scope.launch {
                if (closed) return@launch
                val detail = if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    products.productDetailsList.firstOrNull { it.productId == PRODUCT_ID }
                } else null
                val match = detail?.subscriptionOfferDetails.orEmpty()
                    .asSequence()
                    .filter { it.basePlanId == PREPAID_BASE_PLAN_ID && it.offerId == null }
                    .mapNotNull { offer ->
                        val phase = offer.pricingPhases.pricingPhaseList.lastOrNull()
                        if (phase != null &&
                            phase.billingPeriod == PREPAID_BILLING_PERIOD &&
                            phase.recurrenceMode == ProductDetails.RecurrenceMode.NON_RECURRING &&
                            offer.offerToken.isNotBlank()
                        ) offer to phase else null
                    }
                    .firstOrNull()
                val selection = if (detail != null && match != null) {
                    PrepaidPlan(detail, match.first, match.second)
                } else null
                val oldNotice = _state.value.notice
                _state.value = _state.value.copy(
                    playUnitPrice = selection?.phase?.formattedPrice,
                    playPriceMicros = selection?.phase?.priceAmountMicros,
                    playCurrency = selection?.phase?.priceCurrencyCode,
                    notice = if (selection == null) Notice.UNAVAILABLE
                        else if (oldNotice == Notice.UNAVAILABLE) Notice.NONE else oldNotice
                )
                callback?.invoke(selection)
            }
        }
    }

    /** Buy one prepaid year. Buying again while active is a one-year top-up. */
    fun launchPurchase(activity: Activity) {
        if (closed || !billingClient.isReady || activity.isFinishing || activity.isDestroyed) {
            _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
            if (!closed && !billingClient.isReady) start()
            return
        }
        val deviceId = DeviceUtils.fingerprint(app)
        if (deviceId.isNullOrBlank()) {
            _state.value = _state.value.copy(
                processing = false,
                deviceIdAvailable = false,
                notice = Notice.DEVICE_BINDING_UNAVAILABLE
            )
            return
        }
        _state.value = _state.value.copy(processing = true, notice = Notice.NONE)
        queryPrepaidPlan { selected ->
            if (selected == null) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
                return@queryPrepaidPlan
            }
            val item = BillingFlowParams.ProductDetailsParams.newBuilder()
                .setProductDetails(selected.details)
                .setOfferToken(selected.offer.offerToken)
                .build()
            val params = BillingFlowParams.newBuilder()
                .setObfuscatedAccountId(deviceId)
                .setProductDetailsParamsList(listOf(item))
                .build()
            val launch = billingClient.launchBillingFlow(activity, params)
            if (launch.responseCode != BillingClient.BillingResponseCode.OK) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
            }
        }
    }

    /** Explicit Restore / Check action. */
    fun restoreProLicenseFromPlayStore() {
        if (closed) return
        if (!billingClient.isReady) {
            _state.value = _state.value.copy(notice = Notice.UNAVAILABLE)
            start()
            return
        }
        _state.value = _state.value.copy(processing = true, notice = Notice.RECHECK)
        billingClient.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder()
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
        ) { result, purchases ->
            if (closed) return@queryPurchasesAsync
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
                return@queryPurchasesAsync
            }
            val active = purchases.filter { PRODUCT_ID in it.products }
            if (active.isEmpty()) {
                refreshLocalStatus()
                _state.value = _state.value.copy(processing = false, notice = Notice.NONE)
            } else {
                active.forEach(::processPrepaidPurchase)
            }
        }
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        if (closed) return
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                val matching = purchases.orEmpty().filter { PRODUCT_ID in it.products }
                if (matching.isEmpty()) {
                    _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                } else {
                    matching.forEach(::processPrepaidPurchase)
                }
            }
            BillingClient.BillingResponseCode.USER_CANCELED ->
                _state.value = _state.value.copy(processing = false, notice = Notice.CANCELED)
            else -> _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
        }
    }

    private fun processPrepaidPurchase(purchase: Purchase) {
        if (PRODUCT_ID !in purchase.products) return
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) {
            _state.value = _state.value.copy(processing = false, notice = Notice.PENDING)
            return
        }

        val currentDeviceId = DeviceUtils.fingerprint(app)
        val purchasedDeviceId = purchase.accountIdentifiers?.obfuscatedAccountId
        when {
            currentDeviceId.isNullOrBlank() || purchasedDeviceId.isNullOrBlank() -> {
                rejectDeviceBinding(Notice.DEVICE_BINDING_UNAVAILABLE)
                return
            }
            !sameIdentifier(currentDeviceId, purchasedDeviceId) -> {
                rejectDeviceBinding(Notice.DEVICE_MISMATCH)
                return
            }
            purchase.purchaseTime <= 0L -> {
                _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                return
            }
        }

        scope.launch {
            val granted = withContext(Dispatchers.IO) {
                ledger.grantPrepaidSubscription(purchase.purchaseToken, purchase.purchaseTime)
            }
            if (!granted) {
                _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
                return@launch
            }
            refreshLocalStatus()
            com.vibesync.antivirus.core.worker.ModelUpdateScheduler.ensureCadence(app, pro = true)
            acknowledgePrepaidPurchase(purchase)
        }
    }

    private fun rejectDeviceBinding(notice: Notice) {
        scope.launch {
            withContext(Dispatchers.IO) { ledger.clearForDeviceMismatch() }
            _state.value = _state.value.copy(
                processing = false,
                proActive = false,
                expiresAt = 0L,
                deviceIdAvailable = DeviceUtils.fingerprint(app) != null,
                notice = notice
            )
        }
    }

    private fun sameIdentifier(first: String, second: String): Boolean =
        MessageDigest.isEqual(
            first.toByteArray(Charsets.US_ASCII),
            second.toByteArray(Charsets.US_ASCII)
        )

    /** Every confirmed prepaid purchase/top-up is acknowledged, never consumed. */
    private fun acknowledgePrepaidPurchase(purchase: Purchase) {
        if (purchase.isAcknowledged) {
            _state.value = _state.value.copy(processing = false, notice = Notice.SUCCESS)
            return
        }
        if (closed || !billingClient.isReady) {
            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
            return
        }
        billingClient.acknowledgePurchase(
            AcknowledgePurchaseParams.newBuilder()
                .setPurchaseToken(purchase.purchaseToken)
                .build()
        ) { acknowledgement ->
            if (closed) return@acknowledgePurchase
            _state.value = _state.value.copy(
                processing = false,
                notice = if (acknowledgement.responseCode == BillingClient.BillingResponseCode.OK) {
                    Notice.SUCCESS
                } else {
                    Notice.RECHECK
                }
            )
        }
    }

    fun close() {
        closed = true
        connecting = false
        scope.cancel()
        billingClient.endConnection()
    }

    companion object {
        const val PRODUCT_ID = "pro_access"
        const val PREPAID_BASE_PLAN_ID = "prepaid-1-year"
        const val PREPAID_BILLING_PERIOD = "P1Y"
    }
}
