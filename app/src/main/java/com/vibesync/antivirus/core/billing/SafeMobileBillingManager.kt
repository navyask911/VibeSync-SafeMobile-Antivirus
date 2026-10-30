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

/** One-time consumable years, locally delivered. Device binding stays local;
 * Google Play handles payments and consumption. There is no developer-server entitlement.
 * Consumed passes cannot be restored after app data or encryption keys are lost.
 */
class SafeMobileBillingManager(context: Context) : PurchasesUpdatedListener {
    private val app = context.applicationContext
    private val ledger = ProEntitlementStore(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow(BillingUiState())
    val state: StateFlow<BillingUiState> = _state.asStateFlow()
    private var closed = false
    private var connecting = false
    private val billingClient = BillingClient.newBuilder(app)
        .setListener(this)
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
        val notice: Notice = Notice.NONE,
    )
    enum class Notice { NONE, UNAVAILABLE, CANCELED, PENDING, RECHECK, DEVICE_STORAGE_ERROR, SUCCESS,
        QUANTITY_IN_PLAY_CART, CANNOT_RESTORE }

    fun checkProStatusForThisDevice(): Boolean = ledger.checkProStatusForThisDevice()

    fun refreshLocalStatus() {
        scope.launch {
            val expiry = withContext(Dispatchers.IO) { ledger.expiresAt() }
            _state.value = _state.value.copy(proActive = expiry > System.currentTimeMillis(), expiresAt = expiry)
        }
    }

    fun start() {
        if (closed || connecting) return
        refreshLocalStatus()
        if (billingClient.isReady) {
            _state.value = _state.value.copy(connected = true)
            queryPrice()
            recoverUnconsumedPurchases()
            return
        }
        connecting = true
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingServiceDisconnected() {
                if (closed) return
                connecting = false
                _state.value = _state.value.copy(connected = false, processing = false,
                    notice = Notice.UNAVAILABLE)
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
                recoverUnconsumedPurchases()
            }
        })
    }

    private fun recoverUnconsumedPurchases() {
        // Recover only still-unconsumed transactions. The local status button never queries Play.
        billingClient.queryPurchasesAsync(QueryPurchasesParams.newBuilder()
            .setProductType(BillingClient.ProductType.INAPP).build()) { result, purchases ->
            if (result.responseCode == BillingClient.BillingResponseCode.OK && !closed)
                purchases.forEach(::processPurchase)
        }
    }

    private data class PurchasableProduct(val details: ProductDetails,
        val offer: ProductDetails.OneTimePurchaseOfferDetails)

    private fun queryPrice(callback: ((PurchasableProduct?) -> Unit)? = null) {
        if (!billingClient.isReady || closed) {
            callback?.invoke(null)
            return
        }
        val product = QueryProductDetailsParams.Product.newBuilder()
            .setProductId(PRODUCT_ID)
            .setProductType(BillingClient.ProductType.INAPP).build()
        billingClient.queryProductDetailsAsync(
            QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()
        ) { result, products ->
            // Billing 8 returns QueryProductDetailsResult, including unfetched products.
            // Complete the UI callback on Main before launchBillingFlow touches an Activity.
            scope.launch {
                if (closed) return@launch
                val detail = if (result.responseCode == BillingClient.BillingResponseCode.OK)
                    products.productDetailsList.firstOrNull { it.productId == PRODUCT_ID } else null
                val offers = detail?.oneTimePurchaseOfferDetailsList.orEmpty().ifEmpty {
                    listOfNotNull(detail?.oneTimePurchaseOfferDetails)
                }
                // A yearly pass is a buy product, not a rental or an unfulfilled preorder.
                val oneTime = offers.firstOrNull { it.rentalDetails == null && it.preorderDetails == null }
                val selection = if (detail != null && oneTime != null) PurchasableProduct(detail, oneTime) else null
                val previousNotice = _state.value.notice
                _state.value = _state.value.copy(
                playUnitPrice = oneTime?.formattedPrice,
                playPriceMicros = oneTime?.priceAmountMicros,
                playCurrency = oneTime?.priceCurrencyCode,
                notice = if (selection == null) Notice.UNAVAILABLE
                    else if (previousNotice == Notice.UNAVAILABLE) Notice.NONE else previousNotice
                )
                callback?.invoke(selection)
            }
        }
    }

    /** Quantity is selected in the Google Play cart, NOT settable through
     * ProductDetailsParams.Builder. Actual Purchase.quantity wins.
     * This argument controls only the suggested years displayed to the user.
     */
    fun launchPurchase(activity: Activity, quantity: Int) {
        require(quantity in 1..ProEntitlementStore.MAX_YEARS)
        if (closed || !billingClient.isReady) {
            _state.value = _state.value.copy(notice = Notice.UNAVAILABLE)
            return
        }
        _state.value = _state.value.copy(processing = true, notice = Notice.QUANTITY_IN_PLAY_CART)
        queryPrice { selection ->
            if (selection == null) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
                return@queryPrice
            }
            val item = BillingFlowParams.ProductDetailsParams.newBuilder()
                .setProductDetails(selection.details)
            selection.offer.offerToken?.takeIf { it.isNotBlank() }?.let(item::setOfferToken)
            val params = BillingFlowParams.newBuilder().setProductDetailsParamsList(listOf(item.build())).build()
            val result = billingClient.launchBillingFlow(activity, params)
            if (result.responseCode != BillingClient.BillingResponseCode.OK)
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
        }
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        if (closed) return
        when (result.responseCode) {
            BillingClient.BillingResponseCode.OK -> {
                if (purchases.isNullOrEmpty()) {
                    _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                } else purchases.forEach(::processPurchase)
            }
            BillingClient.BillingResponseCode.USER_CANCELED ->
                _state.value = _state.value.copy(processing = false, notice = Notice.CANCELED)
            else -> _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
        }
    }

    private fun processPurchase(purchase: Purchase) {
        if (PRODUCT_ID !in purchase.products) return
        if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) {
            _state.value = _state.value.copy(processing = false, notice = Notice.PENDING)
            return
        }
        val quantity = purchase.quantity
        if (quantity <= 0) {
            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
            return
        }
        scope.launch {
            val granted = withContext(Dispatchers.IO) { ledger.grant(purchase.purchaseToken, quantity) }
            if (!granted) {
                _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
                return@launch
            }
            refreshLocalStatus()
            com.vibesync.antivirus.core.worker.ModelUpdateScheduler.ensureCadence(app, pro = true)
            _state.value = _state.value.copy(processing = false, notice = Notice.SUCCESS)
            if (!closed && billingClient.isReady) {
                billingClient.consumeAsync(
                    ConsumeParams.newBuilder().setPurchaseToken(purchase.purchaseToken).build()
                ) { consumption, _ ->
                    if (consumption.responseCode != BillingClient.BillingResponseCode.OK)
                        _state.value = _state.value.copy(notice = Notice.RECHECK)
                }
            }
        }
    }

    /** Purely local check. Consumed Google Play products cannot be re-downloaded. */
    fun restoreLocalOnly() {
        refreshLocalStatus()
        _state.value = _state.value.copy(notice = Notice.CANNOT_RESTORE)
    }

    fun close() {
        closed = true
        connecting = false
        scope.cancel()
        billingClient.endConnection()
    }

    companion object {
        const val PRODUCT_ID = "safemobile_pro_1_year"
    }
}
