package com.vibesync.antivirus.core.billing

import android.app.Activity
import android.content.Context
import android.util.Log
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
 *
 * Billing is optional at runtime: sideloaded installs, missing Play products,
 * and Play service failures leave the app usable with Pro purchase disabled.
 */
class SafeMobileBillingManager(context: Context) : PurchasesUpdatedListener {
    private val app = context.applicationContext
    private val ledger = try {
        ProEntitlementStore(app)
    } catch (error: Exception) {
        Log.e(TAG, "Could not initialize the local Pro entitlement store.", error)
        null
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val _state = MutableStateFlow(
        BillingUiState(deviceIdAvailable = safeDeviceFingerprint() != null)
    )
    val state: StateFlow<BillingUiState> = _state.asStateFlow()
    private var closed = false
    private var connecting = false

    /**
     * BillingClient construction can throw on unsupported/sideloaded environments.
     * Keep a null client and expose an unavailable state rather than failing app startup.
     */
    private val billingClient: BillingClient? = try {
        BillingClient.newBuilder(app)
            .setListener(this)
            .enablePendingPurchases(
                PendingPurchasesParams.newBuilder()
                    .enableOneTimeProducts()
                    .enablePrepaidPlans()
                    .build()
            )
            .enableAutoServiceReconnection()
            .build()
    } catch (error: Exception) {
        Log.w(TAG, "Google Play Billing could not be initialized; Pro purchases are disabled.", error)
        _state.value = _state.value.copy(notice = Notice.UNAVAILABLE)
        null
    }

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

    fun checkProStatusForThisDevice(): Boolean = try {
        ledger?.checkProStatusForThisDevice() == true
    } catch (error: Exception) {
        Log.e(TAG, "Could not read the local Pro entitlement.", error)
        false
    }

    private fun safeDeviceFingerprint(): String? = try {
        DeviceUtils.fingerprint(app)
    } catch (error: Exception) {
        Log.w(TAG, "Device binding fingerprint is unavailable.", error)
        null
    }

    private fun setUnavailable(error: Exception? = null) {
        if (error != null) Log.w(TAG, "Google Play Billing operation failed; purchase flow disabled.", error)
        _state.value = _state.value.copy(
            connected = false,
            processing = false,
            notice = Notice.UNAVAILABLE
        )
    }

    private fun setResponseNotice(responseCode: Int, processing: Boolean = false) {
        val notice = when (responseCode) {
            BillingClient.BillingResponseCode.OK -> Notice.NONE
            BillingClient.BillingResponseCode.USER_CANCELED -> Notice.CANCELED
            BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED -> Notice.RECHECK
            BillingClient.BillingResponseCode.ITEM_NOT_OWNED -> Notice.RECHECK
            BillingClient.BillingResponseCode.BILLING_UNAVAILABLE -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.DEVELOPER_ERROR -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.ERROR -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.ITEM_UNAVAILABLE -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.NETWORK_ERROR -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.SERVICE_DISCONNECTED -> Notice.UNAVAILABLE
            BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE -> Notice.UNAVAILABLE
            else -> Notice.UNAVAILABLE
        }
        val connected = when (notice) {
            Notice.NONE -> true
            Notice.UNAVAILABLE -> false
            else -> _state.value.connected
        }
        _state.value = _state.value.copy(
            connected = connected,
            processing = processing,
            notice = notice
        )
    }

    private fun isBillingReady(client: BillingClient? = billingClient): Boolean = try {
        client?.isReady == true
    } catch (error: Exception) {
        setUnavailable(error)
        false
    }

    fun refreshLocalStatus() {
        scope.launch {
            val expiry = try {
                withContext(Dispatchers.IO) { ledger?.expiresAt() ?: 0L }
            } catch (error: Exception) {
                Log.e(TAG, "Could not refresh the local Pro entitlement.", error)
                0L
            }
            _state.value = _state.value.copy(
                proActive = expiry > System.currentTimeMillis(),
                expiresAt = expiry,
                deviceIdAvailable = safeDeviceFingerprint() != null
            )
        }
    }

    /** Called from Application on process launch and when the paywall resumes. */
    fun start() {
        if (closed || connecting) return
        refreshLocalStatus()
        val client = billingClient
        if (client == null) {
            setUnavailable()
            return
        }
        if (isBillingReady(client)) {
            _state.value = _state.value.copy(connected = true)
            queryPrepaidPlan()
            recoverPurchases()
            return
        }

        connecting = true
        try {
            client.startConnection(object : BillingClientStateListener {
                override fun onBillingServiceDisconnected() {
                    if (closed) return
                    connecting = false
                    setUnavailable()
                }

                override fun onBillingSetupFinished(result: BillingResult) {
                    if (closed) return
                    connecting = false
                    try {
                        when (result.responseCode) {
                            BillingClient.BillingResponseCode.OK -> {
                                _state.value = _state.value.copy(connected = true, notice = Notice.NONE)
                                queryPrepaidPlan()
                                recoverPurchases()
                            }
                            BillingClient.BillingResponseCode.USER_CANCELED -> setResponseNotice(result.responseCode)
                            BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                            BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                            BillingClient.BillingResponseCode.ERROR,
                            BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                            BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                            BillingClient.BillingResponseCode.ITEM_NOT_OWNED,
                            BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                            BillingClient.BillingResponseCode.NETWORK_ERROR,
                            BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                            BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE -> setResponseNotice(result.responseCode)
                            else -> setUnavailable()
                        }
                    } catch (error: Exception) {
                        setUnavailable(error)
                    }
                }
            })
        } catch (error: Exception) {
            connecting = false
            setUnavailable(error)
        }
    }

    /** Restore active prepaid purchases from Play every time the app starts. */
    private fun recoverPurchases() {
        val client = billingClient
        if (closed || !isBillingReady(client)) return
        try {
            client?.queryPurchasesAsync(
                QueryPurchasesParams.newBuilder()
                    .setProductType(BillingClient.ProductType.SUBS)
                    .build()
            ) { result, purchases ->
                if (closed) return@queryPurchasesAsync
                try {
                    when (result.responseCode) {
                        BillingClient.BillingResponseCode.OK -> {
                            val active = purchases.filter { PRODUCT_ID in it.products }
                            if (active.isNotEmpty()) active.forEach(::processPrepaidPurchase)
                            else refreshLocalStatus()
                        }
                        BillingClient.BillingResponseCode.USER_CANCELED -> setResponseNotice(result.responseCode)
                        BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                        BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                        BillingClient.BillingResponseCode.ERROR,
                        BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                        BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                        BillingClient.BillingResponseCode.ITEM_NOT_OWNED,
                        BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                        BillingClient.BillingResponseCode.NETWORK_ERROR,
                        BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                        BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE -> setResponseNotice(result.responseCode)
                        else -> setUnavailable()
                    }
                } catch (error: Exception) {
                    setUnavailable(error)
                }
            }
        } catch (error: Exception) {
            setUnavailable(error)
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
        val client = billingClient
        if (closed || !isBillingReady(client)) {
            callback?.invoke(null)
            return
        }

        try {
            val product = QueryProductDetailsParams.Product.newBuilder()
                .setProductId(PRODUCT_ID)
                .setProductType(BillingClient.ProductType.SUBS)
                .build()
            client?.queryProductDetailsAsync(
                QueryProductDetailsParams.newBuilder().setProductList(listOf(product)).build()
            ) { result, products ->
                scope.launch {
                    if (closed) return@launch
                    try {
                        val detail = when (result.responseCode) {
                            BillingClient.BillingResponseCode.OK ->
                                products.productDetailsList.firstOrNull { it.productId == PRODUCT_ID }
                            BillingClient.BillingResponseCode.USER_CANCELED -> {
                                setResponseNotice(result.responseCode)
                                null
                            }
                            BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                            BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                            BillingClient.BillingResponseCode.ERROR,
                            BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                            BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                            BillingClient.BillingResponseCode.ITEM_NOT_OWNED,
                            BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                            BillingClient.BillingResponseCode.NETWORK_ERROR,
                            BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                            BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE -> {
                                setResponseNotice(result.responseCode)
                                null
                            }
                            else -> {
                                setUnavailable()
                                null
                            }
                        }
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

                        if (selection == null && result.responseCode == BillingClient.BillingResponseCode.OK) {
                            // Missing product/base plan is normal for sideloaded builds and unconfigured Play Console products.
                            setUnavailable()
                        } else if (selection != null) {
                            _state.value = _state.value.copy(
                                playUnitPrice = selection.phase.formattedPrice,
                                playPriceMicros = selection.phase.priceAmountMicros,
                                playCurrency = selection.phase.priceCurrencyCode,
                                notice = if (_state.value.notice == Notice.UNAVAILABLE) Notice.NONE else _state.value.notice
                            )
                        } else {
                            _state.value = _state.value.copy(
                                playUnitPrice = null,
                                playPriceMicros = null,
                                playCurrency = null
                            )
                        }
                        callback?.invoke(selection)
                    } catch (error: Exception) {
                        setUnavailable(error)
                        callback?.invoke(null)
                    }
                }
            }
        } catch (error: Exception) {
            setUnavailable(error)
            callback?.invoke(null)
        }
    }

    /** Buy one prepaid year. Buying again while active is a one-year top-up. */
    fun launchPurchase(activity: Activity) {
        try {
            if (closed || !isBillingReady()) {
                setUnavailable()
                if (!closed) start()
                return
            }
            if (activity.isFinishing || activity.isDestroyed) {
                setUnavailable()
                return
            }
            val deviceId = safeDeviceFingerprint()
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
                    setUnavailable()
                    return@queryPrepaidPlan
                }
                try {
                    val client = billingClient
                    if (closed || !isBillingReady(client)) {
                        setUnavailable()
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
                    val launch = client!!.launchBillingFlow(activity, params)
                    when (launch.responseCode) {
                        BillingClient.BillingResponseCode.OK ->
                            _state.value = _state.value.copy(processing = true, connected = true, notice = Notice.NONE)
                        BillingClient.BillingResponseCode.USER_CANCELED ->
                            setResponseNotice(launch.responseCode)
                        BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                        BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                        BillingClient.BillingResponseCode.ERROR,
                        BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                        BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                        BillingClient.BillingResponseCode.ITEM_NOT_OWNED,
                        BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                        BillingClient.BillingResponseCode.NETWORK_ERROR,
                        BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                        BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE ->
                            setResponseNotice(launch.responseCode)
                        else -> setUnavailable()
                    }
                } catch (error: Exception) {
                    setUnavailable(error)
                }
            }
        } catch (error: Exception) {
            setUnavailable(error)
        }
    }

    /** Explicit Restore / Check action. */
    fun restoreProLicenseFromPlayStore() {
        try {
            if (closed) return
            if (!isBillingReady()) {
                setUnavailable()
                start()
                return
            }
            _state.value = _state.value.copy(processing = true, notice = Notice.RECHECK)
            billingClient?.queryPurchasesAsync(
                QueryPurchasesParams.newBuilder()
                    .setProductType(BillingClient.ProductType.SUBS)
                    .build()
            ) { result, purchases ->
                if (closed) return@queryPurchasesAsync
                try {
                    when (result.responseCode) {
                        BillingClient.BillingResponseCode.OK -> {
                            val active = purchases.filter { PRODUCT_ID in it.products }
                            if (active.isEmpty()) {
                                refreshLocalStatus()
                                _state.value = _state.value.copy(processing = false, notice = Notice.NONE)
                            } else {
                                active.forEach(::processPrepaidPurchase)
                            }
                        }
                        BillingClient.BillingResponseCode.USER_CANCELED ->
                            setResponseNotice(result.responseCode)
                        BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                        BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                        BillingClient.BillingResponseCode.ERROR,
                        BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                        BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                        BillingClient.BillingResponseCode.ITEM_NOT_OWNED,
                        BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                        BillingClient.BillingResponseCode.NETWORK_ERROR,
                        BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                        BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE ->
                            setResponseNotice(result.responseCode)
                        else -> setUnavailable()
                    }
                } catch (error: Exception) {
                    setUnavailable(error)
                }
            }
        } catch (error: Exception) {
            setUnavailable(error)
        }
    }

    override fun onPurchasesUpdated(result: BillingResult, purchases: MutableList<Purchase>?) {
        if (closed) return
        try {
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
                BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                BillingClient.BillingResponseCode.ITEM_NOT_OWNED ->
                    setResponseNotice(result.responseCode)
                BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                BillingClient.BillingResponseCode.ERROR,
                BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                BillingClient.BillingResponseCode.NETWORK_ERROR,
                BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE ->
                    setResponseNotice(result.responseCode)
                else -> setUnavailable()
            }
        } catch (error: Exception) {
            setUnavailable(error)
        }
    }

    private fun processPrepaidPurchase(purchase: Purchase) {
        try {
            if (PRODUCT_ID !in purchase.products) return
            if (purchase.purchaseState != Purchase.PurchaseState.PURCHASED) {
                _state.value = _state.value.copy(processing = false, notice = Notice.PENDING)
                return
            }

            val currentDeviceId = safeDeviceFingerprint()
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
                try {
                    val granted = withContext(Dispatchers.IO) {
                        ledger?.grantPrepaidSubscription(purchase.purchaseToken, purchase.purchaseTime) == true
                    }
                    if (!granted) {
                        _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
                        return@launch
                    }
                    refreshLocalStatus()
                    com.vibesync.antivirus.core.worker.ModelUpdateScheduler.ensureCadence(app, pro = true)
                    acknowledgePrepaidPurchase(purchase)
                } catch (error: Exception) {
                    Log.e(TAG, "Could not apply the verified Pro purchase to local storage.", error)
                    _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
                }
            }
        } catch (error: Exception) {
            setUnavailable(error)
        }
    }

    private fun rejectDeviceBinding(notice: Notice) {
        scope.launch {
            try {
                withContext(Dispatchers.IO) { ledger?.clearForDeviceMismatch() }
                _state.value = _state.value.copy(
                    processing = false,
                    proActive = false,
                    expiresAt = 0L,
                    deviceIdAvailable = safeDeviceFingerprint() != null,
                    notice = notice
                )
            } catch (error: Exception) {
                Log.e(TAG, "Could not clear a mismatched local Pro entitlement.", error)
                _state.value = _state.value.copy(processing = false, notice = Notice.DEVICE_STORAGE_ERROR)
            }
        }
    }

    private fun sameIdentifier(first: String, second: String): Boolean =
        MessageDigest.isEqual(
            first.toByteArray(Charsets.US_ASCII),
            second.toByteArray(Charsets.US_ASCII)
        )

    /** Every confirmed prepaid purchase/top-up is acknowledged, never consumed. */
    private fun acknowledgePrepaidPurchase(purchase: Purchase) {
        try {
            if (purchase.isAcknowledged) {
                _state.value = _state.value.copy(processing = false, notice = Notice.SUCCESS)
                return
            }
            val client = billingClient
            if (closed || !isBillingReady(client)) {
                _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                return
            }
            client?.acknowledgePurchase(
                AcknowledgePurchaseParams.newBuilder()
                    .setPurchaseToken(purchase.purchaseToken)
                    .build()
            ) { acknowledgement ->
                if (closed) return@acknowledgePurchase
                try {
                    when (acknowledgement.responseCode) {
                        BillingClient.BillingResponseCode.OK ->
                            _state.value = _state.value.copy(processing = false, notice = Notice.SUCCESS)
                        BillingClient.BillingResponseCode.USER_CANCELED,
                        BillingClient.BillingResponseCode.BILLING_UNAVAILABLE,
                        BillingClient.BillingResponseCode.DEVELOPER_ERROR,
                        BillingClient.BillingResponseCode.ERROR,
                        BillingClient.BillingResponseCode.FEATURE_NOT_SUPPORTED,
                        BillingClient.BillingResponseCode.ITEM_ALREADY_OWNED,
                        BillingClient.BillingResponseCode.ITEM_NOT_OWNED,
                        BillingClient.BillingResponseCode.ITEM_UNAVAILABLE,
                        BillingClient.BillingResponseCode.NETWORK_ERROR,
                        BillingClient.BillingResponseCode.SERVICE_DISCONNECTED,
                        BillingClient.BillingResponseCode.SERVICE_UNAVAILABLE ->
                            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                        else ->
                            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                    }
                } catch (error: Exception) {
                    _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
                    Log.w(TAG, "Could not process the Play purchase acknowledgement response.", error)
                }
            }
        } catch (error: Exception) {
            _state.value = _state.value.copy(processing = false, notice = Notice.RECHECK)
            Log.w(TAG, "Could not acknowledge the Play purchase.", error)
        }
    }

    fun close() {
        closed = true
        connecting = false
        scope.cancel()
        try {
            billingClient?.endConnection()
        } catch (error: Exception) {
            Log.w(TAG, "Could not close the Google Play Billing connection cleanly.", error)
        }
    }

    companion object {
        private const val TAG = "SafeMobileBilling"
        const val PRODUCT_ID = "pro_access"
        const val PREPAID_BASE_PLAN_ID = "prepaid-1-year"
        const val PREPAID_BILLING_PERIOD = "P1Y"
    }
}
