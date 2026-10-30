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

/** One-time consumable years, locally delivered. No user identifiers leave the app.
 * NOTE: Consumables cannot be restored after consumption by Google Play.
 */
class SafeMobileBillingManager(context: Context) : PurchasesUpdatedListener {
    private val app = context.applicationContext
    private val ledger = ProEntitlementStore(app)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow(BillingUiState())
    val state: StateFlow<BillingUiState> = _state.asStateFlow()
    private var closed = false
    private val billingClient = BillingClient.newBuilder(app)
        .setListener(this)
        .enablePendingPurchases(PendingPurchasesParams.newBuilder().enableOneTimeProducts().build())
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
        if (closed || billingClient.isReady) return
        refreshLocalStatus()
        billingClient.startConnection(object : BillingClientStateListener {
            override fun onBillingServiceDisconnected() {
                _state.value = _state.value.copy(connected = false, processing = false,
                    notice = Notice.UNAVAILABLE)
            }
            override fun onBillingSetupFinished(result: BillingResult) {
                if (closed) return
                if (result.responseCode != BillingClient.BillingResponseCode.OK) {
                    _state.value = _state.value.copy(connected = false, notice = Notice.UNAVAILABLE)
                    return
                }
                _state.value = _state.value.copy(connected = true)
                queryPrice()
                // Recover only Play-unconsumed PENDING/PURCHASED transactions, not consumed
                // entitlements. Restore/Check Status button never queries Google servers.
                billingClient.queryPurchasesAsync(
                    QueryPurchasesParams.newBuilder()
                        .setProductType(BillingClient.ProductType.INAPP).build()
                ) { status, purchases ->
                    if (status.responseCode == BillingClient.BillingResponseCode.OK && !closed)
                        purchases.forEach(::processPurchase)
                }
            }
        })
    }

    private fun queryPrice(callback: ((ProductDetails?) -> Unit)? = null) {
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
            if (closed) return@queryProductDetailsAsync
            val detail = if (result.responseCode == BillingClient.BillingResponseCode.OK)
                products.firstOrNull { it.productId == PRODUCT_ID } else null
            val oneTime = detail?.oneTimePurchaseOfferDetails
            _state.value = _state.value.copy(
                playUnitPrice = oneTime?.formattedPrice,
                playPriceMicros = oneTime?.priceAmountMicros,
                playCurrency = oneTime?.priceCurrencyCode,
                notice = if (detail == null) Notice.UNAVAILABLE else _state.value.notice
            )
            callback?.invoke(detail)
        }
    }

    /** Quantity is selected in the Google Play cart, NOT settable through
     * ProductDetailsParams.Builder in Billing 7.1.1. Actual Purchase.quantity wins.
     * This argument controls only the suggested years displayed to the user.
     */
    fun launchPurchase(activity: Activity, quantity: Int) {
        require(quantity in 1..ProEntitlementStore.MAX_YEARS)
        if (closed || !billingClient.isReady) {
            _state.value = _state.value.copy(notice = Notice.UNAVAILABLE)
            return
        }
        _state.value = _state.value.copy(processing = true, notice = Notice.QUANTITY_IN_PLAY_CART)
        queryPrice { details ->
            if (details == null) {
                _state.value = _state.value.copy(processing = false, notice = Notice.UNAVAILABLE)
                return@queryPrice
            }
            val params = BillingFlowParams.newBuilder()
                .setProductDetailsParamsList(listOf(
                    BillingFlowParams.ProductDetailsParams.newBuilder()
                        .setProductDetails(details).build()
                )).build()
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
        if (quantity !in 1..ProEntitlementStore.MAX_YEARS) {
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
        scope.cancel()
        billingClient.endConnection()
    }

    companion object {
        const val PRODUCT_ID = "safemobile_pro_1_year"
    }
}
