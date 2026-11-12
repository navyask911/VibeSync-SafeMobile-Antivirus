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

/**
 * Google Play auto-renewing subscription with an encrypted, device-bound local expiry cache.
 * The legacy one-time SKU is queried once per manager lifetime to migrate still-owned purchases.
 * No purchase token, Android ID, scan data or entitlement is sent to a developer server.
 */
class SafeMobileBillingManager(context: Context) : PurchasesUpdatedListener {
    private val app = context.applicationContext
    private val ledger = ProEntitlementStore(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow(BillingUiState())
    val state: StateFlow<BillingUiState> = _state.asStateFlow()
    private var closed = false
    private var connecting = false
    private var legacyRecoveryInFlight = false
    private var legacyRecoveryCompleted = false

    private val billingClient = BillingClient.newBuilder(app)
        .setListener(this)
        // Keep one-time pending support only for the legacy consumable migration query.
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
        .enableAutoServiceReconnection()
        .build()

    data class BillingUiState(
        val connected: Boolean = false,
        val processing: Boolean = false,
        val proActive: Boolean = false,
        val expiresAt: Long = 0L,
        val playUnitPrice: String? = null,
        val playPriceMicros: Long? = null,
        val playCurrency: String? = null,
        val legacyUnitPrice: String? = null,
        val legacyPriceMicros: Long? = null,
        val legacyCurrency: String? = null,
        val notice: Notice = Notice.NONE,
    )

    enum class Notice {
        NONE, UNAVAILABLE, CANCELED, PENDING, RECHECK, DEVICE_STORAGE_ERROR, SUCCESS
    }

    fun checkProStatusForThisDevice(): Boolean = ledger.checkProStatusForThisDevice()

    fun refreshLocalStatus() {
        scope.launch {
            val expiry = withContext(Dispatchers.IO) { ledger.expiresAt() }
            _state.value = _state.value.copy(
                proActive = expiry > System.currentTimeMillis(),
                expiresAt = expiry
            )
        }
    }

    fun start() {
        if (closed || connecting) return
        refreshLocalStatus()
        if (billingClient.isReady) {
            _state.value = _state.value.copy(connected = true)
            queryPrice()
            queryLegacyPassPrice()
            recoverPurchases()
            return
        }
        connecting = true
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingServiceDisconnected() {
                if (closed) return
                connecting = false
                _state.value = _state.value.copy(
                    connected = false,
                    processing = false,
                    notice = Notice.UNAVAILABLE
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
                queryPrice()
                queryLegacyPassPrice()
                recoverPurchases()
            }
        })
    }

    /** Recover current subscriptions first, then attempt the one-time legacy SKU migration. */
    private fun recoverPurchases() {
        if (closed || !billingClient.isReady) return
        billingClient.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder()
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
        ) { result, purchases ->
            if (closed) return@queryPurchasesAsync
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                purchases.filter { PRODUCT_ID in it.products }.forEach(::processSubscriptionPurchase)
            }
            // Still run the legacy lookup if the SUBS lookup succeeded or failed.
            queryLegacyInAppOnce()
        }
    }

    /**
     * Migration lookup for the old consumable SKU. Successful lookup is cached for this
     * manager lifetime; a failed lookup is retried on the next app resume/recovery attempt.
     */
    private fun queryLegacyInAppOnce() {
        if (closed || !billingClient.isReady || legacyRecoveryCompleted || legacyRecoveryInFlight) return
        legacyRecoveryInFlight = true
        billingClient.queryPurchasesAsync(
            QueryPurchasesParams.newBuilder()
                .setProductType(BillingClient.ProductType.INAPP)
                .build()
        ) { result, purchases ->
            legacyRecoveryInFlight = false
            if (closed) return@queryPurchasesAsync
            if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                legacyRecoveryCompleted = true
                purchases.filter { LEGACY_PRODUCT_ID in it.products }.forEach(::processLegacyPurchase)
            }
        }
    }

    private data class PurchasableProduct(
        val details: ProductDetails,
        val offer: ProductDetails.SubscriptionOfferDetails,
        val recurringPrice: ProductDetails.PricingPhase
    )

    private fun queryPrice(callback: ((PurchasableProduct?) -> Unit)? = null) {
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
            // Billing 8 returns QueryProductDetailsResult, including unfetched products.
            scope.launch {
                if (closed) return@launch
                val detail = if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    products.productDetailsList.firstOrNull { it.productId == PRODUCT_ID }
                } else null
                val offerAndPrice = detail?.subscriptionOfferDetails.orEmpty()
                    .asSequence()
                    .mapNotNull { offer ->
                        offer.pricingPhases.pricingPhaseList.lastOrNull()?.let { offer to it }
                    }
                    .firstOrNull()
                val selection = if (detail != null && offerAndPrice != null) {
                    PurchasableProduct(detail, offerAndPrice.first, offerAndPrice.second)
                } else null
                val previousNotice = _state.value.notice
                _state.value = _state.value.copy(
                    playUnitPrice = selection?.recurringPrice?.formattedPrice,
                    playPriceMicros = selection?.recurringPrice?.priceAmountMicros,
                    playCurrency = selection?.recurringPrice?.priceCurrencyCode,
                    notice = if (selection == null) Notice.UNAVAILABLE
                        else if (previousNotice == Notice.UNAVAILABLE) Notice.NONE else previousNotice
                )
                callback?.invoke(selection)
            }
        }
    }

    /**
     * Starts the old annual consumable as an optional prepaid multi-year pass.
     * Google Play owns the quantity control in its purchase sheet; the app cannot
     * inject the slider value into BillingFlowParams. The returned Purchase.quantity
     * is authoritative and is used by processLegacyPurchase() to grant actual years.
     */
    fun launchMultiYearPassPurchase(activity: Activity) {
        if (closed || !billingClient.isReady || activity.isFinishing || activity.isDestroyed) {
            _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
            if (!closed && !billingClient.isReady) start()
            return
        }
        _state.value = _state.value.copy(processing = true, notice = Notice.NONE)
        queryLegacyPassPrice { selection ->
            if (selection == null) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
                return@queryLegacyPassPrice
            }
            val paramsBuilder = BillingFlowParams.ProductDetailsParams.newBuilder()
                .setProductDetails(selection.details)
            selection.offer.offerToken.takeIf { it.isNotBlank() }?.let(paramsBuilder::setOfferToken)
            val params = BillingFlowParams.newBuilder()
                .setProductDetailsParamsList(listOf(paramsBuilder.build()))
                .build()
            val result = billingClient.launchBillingFlow(activity, params)
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
            }
        }
    }

    private data class LegacyPassProduct(
        val details: ProductDetails,
        val offer: ProductDetails.OneTimePurchaseOfferDetails
    )

    private fun queryLegacyPassPrice(callback: ((LegacyPassProduct?) -> Unit)? = null) {
        if (!billingClient.isReady || closed) {
            callback?.invoke(null)
            return
        }
        val product = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(LEGACY_PRODUCT_ID)
            .setProductType(BillingClient.ProductType.INAPP)
            .build()
        billingClient.queryProductDetailsAsync(
            QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()
        ) { result, products ->
            scope.launch {
                if (closed) return@launch
                val detail = if (result.responseCode == BillingClient.BillingResponseCode.OK) {
                    products.productDetailsList.firstOrNull { it.productId == LEGACY_PRODUCT_ID }
                } else null
                // Multi-quantity is supported for eligible buy purchase options,
                // not discount/preorder offers or rentals. The Play Console product must
                // also have Multi-quantity enabled before the cart exposes the quantity picker.
                val eligiblePurchaseOption = detail?.oneTimePurchaseOfferDetailsList
                    ?.firstOrNull { option ->
                        option.priceAmountMicros > 0L &&
                            option.offerId == null &&
                            option.rentalDetails == null &&
                            !option.purchaseOptionId.isNullOrBlank()
                    }
                    ?: detail?.oneTimePurchaseOfferDetails?.takeIf { option ->
                        option.priceAmountMicros > 0L &&
                            option.offerId == null &&
                            option.rentalDetails == null
                    }
                val selection = if (detail != null && eligiblePurchaseOption != null) {
                    LegacyPassProduct(detail, eligiblePurchaseOption)
                } else null
                val priorNotice = _state.value.notice
                _state.value = _state.value.copy(
                    legacyUnitPrice = offer?.formattedPrice,
                    legacyPriceMicros = offer?.priceAmountMicros,
                    legacyCurrency = offer?.priceCurrencyCode,
                    notice = if (selection != null && priorNotice == Notice.UNAVAILABLE) Notice.NONE
                        else priorNotice
                )
                callback?.invoke(selection)
            }
        }
    }

    fun launchPurchase(activity: Activity) {
        if (closed || !billingClient.isReady || activity.isFinishing || activity.isDestroyed) {
            _state.value = _state.value.copy(notice = Notice.UNAVAILABLE)
            return
        }
        _state.value = _state.value.copy(processing = true, notice = Notice.NONE)
        queryPrice { selection ->
            if (selection == null) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
                return@queryPrice
            }
            val item = BillingFlowParams.ProductDetailsParams.newBuilder()
                .setProductDetails(selection.details)
                .setOfferToken(selection.offer.offerToken)
                .build()
            val params = BillingFlowParams.newBuilder()
                .setProductDetailsParamsList(listOf(item))
                .build()
            val result = billingClient.launchBillingFlow(activity, params)
            if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
            }
        }
    }

    /** Explicit restore/check action. Current subscriptions restore from Play; legacy data is local. */
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
            val currentSubscriptions = purchases.filter { PRODUCT_ID in it.products }
            if (currentSubscriptions.isEmpty()) {
                _state.value = _state.value.copy(processing = false, notice = Notice.NONE)
            } else {
                currentSubscriptions.forEach(::processSubscriptionPurchase)
            }
            queryLegacyInAppOnce()
            refreshLocalStatus()
        }
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        if (closed) return
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                if (purchases.isNullOrEmpty()) {
                    _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                } else {
                    purchases.forEach { purchase ->
                        when {
                            PRODUCT_ID in purchase.products -> processSubscriptionPurchase(purchase)
                            LEGACY_PRODUCT_ID in purchase.products -> processLegacyPurchase(purchase)
                        }
                    }
                }
            }
            BillingClient.BillingResponseCode.USER_CANCELED ->
                _state.value = _state.value.copy(processing = false, notice = Notice.CANCELED)
            else -> _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
        }
    }

    private fun processSubscriptionPurchase(purchase: Purchase) {
        if (PRODUCT_ID !in purchase.products) return
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) {
            _state.value = _state.value.copy(processing = false, notice = Notice.PENDING)
            return
        }
        if (purchase.purchaseTime <= 0L) {
            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
            return
        }
        scope.launch {
            val granted = withContext(Dispatchers.IO) {
                ledger.grantSubscription(purchase.purchaseToken, purchase.purchaseTime)
            }
            if (!granted) {
                _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
                return@launch
            }
            refreshLocalStatus()
            com.vibesync.antivirus.core.worker.ModelUpdateScheduler.ensureCadence(app, pro = true)
            acknowledgeSubscriptionPurchase(purchase)
        }
    }

    /** Initial subscription purchases must be acknowledged; renewals are already acknowledged. */
    private fun acknowledgeSubscriptionPurchase(purchase: Purchase) {
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

    /** One-time compatibility grant for an old, still-owned consumable annual pass. */
    private fun processLegacyPurchase(purchase: Purchase) {
        if (LEGACY_PRODUCT_ID !in purchase.products) return
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) {
            _state.value = _state.value.copy(processing = false, notice = Notice.PENDING)
            return
        }
        if (purchase.quantity <= 0) {
            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
            return
        }
        scope.launch {
            val granted = withContext(Dispatchers.IO) {
                ledger.grant(purchase.purchaseToken, purchase.quantity)
            }
            if (!granted) {
                _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
                return@launch
            }
            refreshLocalStatus()
            com.vibesync.antivirus.core.worker.ModelUpdateScheduler.ensureCadence(app, pro = true)
            _state.value = _state.value.copy(processing = false, notice = Notice.SUCCESS)
            // Only old INAPP consumables are consumed. SUBS are never consumed.
            if (!closed && billingClient.isReady) {
                billingClient.consumeAsync(
                    ConsumeParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build()
                ) { consumption, _ ->
                    if (consumption.responseCode != BillingClient.BillingResponseCode.OK) {
                        _state.value = _state.value.copy(notice = Notice.RECHECK)
                    }
                }
            }
        }
    }

    fun close() {
        closed = true
        connecting = false
        scope.cancel()
        billingClient.endConnection()
    }

    companion object {
        const val PRODUCT_ID = "safemobile_pro_1y_subs"
        const val LEGACY_PRODUCT_ID = "safemobile_pro_1_year"
    }
}
