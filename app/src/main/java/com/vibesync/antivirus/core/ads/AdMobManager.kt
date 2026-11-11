package com.vibesync.antivirus.core.ads

import android.app.Activity
import com.google.android.libraries.ads.mobile.sdk.common.AdRequest
import com.google.android.libraries.ads.mobile.sdk.common.PreloadConfiguration
import com.google.android.libraries.ads.mobile.sdk.interstitial.InterstitialAdPreloader
import com.google.android.ump.ConsentInformation
import com.google.android.ump.ConsentRequestParameters
import com.google.android.ump.UserMessagingPlatform
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

data class AdMobUiState(
    /** Unknown Pro status is represented as Pro so the UI fails closed. */
    val isPro: Boolean = true,
    val adsReady: Boolean = false,
    val privacyOptionsRequired: Boolean = false
)

/** Consent-aware AdMob manager. Both the Pro entitlement and UMP consent gate every request. */
class AdMobManager(context: android.content.Context) {
    private val app = context.applicationContext as SafeMobileApp
    private val refreshMutex = Mutex()
    private val mutableState = MutableStateFlow(AdMobUiState())
    val state: StateFlow<AdMobUiState> = mutableState.asStateFlow()
    private var consentInfoUpdated = false
    private var interstitialPreloaderStarted = false

    val bannerUnitId: String
        get() = if (BuildConfig.DEBUG) TEST_BANNER_UNIT_ID else BANNER_UNIT_ID

    private val interstitialUnitId: String
        get() = if (BuildConfig.DEBUG) TEST_INTERSTITIAL_UNIT_ID else INTERSTITIAL_UNIT_ID

    /** UMP consent information is refreshed once every app-process launch. */
    suspend fun refresh(activity: Activity) = refreshMutex.withLock {
        if (activity.isFinishing || activity.isDestroyed) return@withLock
        if (app.isProForAdMob()) {
            disableForProInternal()
            return@withLock
        }

        val consent = UserMessagingPlatform.getConsentInformation(app)
        if (!consentInfoUpdated) {
            consentInfoUpdated = true
            runCatching { updateConsentAndShowRequiredForm(activity, consent) }
        }
        val privacyOptionsRequired = runCatching {
            consent.privacyOptionsRequirementStatus ==
                ConsentInformation.PrivacyOptionsRequirementStatus.REQUIRED
        }.getOrDefault(false)
        val consentAllowsAds = runCatching { consent.canRequestAds() }.getOrDefault(false)
        if (!AdMobEligibilityPolicy.shouldRequestAds(isPro = false, consentAllowsAds = consentAllowsAds)) {
            mutableState.value = AdMobUiState(
                isPro = false,
                adsReady = false,
                privacyOptionsRequired = privacyOptionsRequired
            )
            return@withLock
        }

        val initialized = app.initializeMobileAdsForFreeTier()
        if (app.isProForAdMob()) {
            disableForProInternal()
            return@withLock
        }
        if (initialized && !interstitialPreloaderStarted) {
            runCatching {
                val request = AdRequest.Builder(interstitialUnitId).build()
                InterstitialAdPreloader.start(interstitialUnitId, PreloadConfiguration(request))
                interstitialPreloaderStarted = true
            }
        }
        mutableState.value = AdMobUiState(
            isPro = false,
            adsReady = initialized,
            privacyOptionsRequired = privacyOptionsRequired
        )
    }

    private suspend fun updateConsentAndShowRequiredForm(
        activity: Activity,
        consent: ConsentInformation
    ) = suspendCancellableCoroutine<Unit> { continuation ->
        try {
            consent.requestConsentInfoUpdate(
                activity,
                ConsentRequestParameters.Builder().build(),
                {
                    UserMessagingPlatform.loadAndShowConsentFormIfRequired(activity) {
                        if (continuation.isActive) continuation.resume(Unit)
                    }
                },
                {
                    // A previous valid consent decision may still allow ads after update failure.
                    if (continuation.isActive) continuation.resume(Unit)
                }
            )
        } catch (_: Exception) {
            if (continuation.isActive) continuation.resume(Unit)
        }
    }

    /** Re-check local Pro and the current UMP decision before every banner load. */
    suspend fun canRequestAdsNow(): Boolean {
        if (app.isProForAdMob()) {
            disableForProInternal()
            return false
        }
        if (!mutableState.value.adsReady || mutableState.value.isPro) return false
        val consentAllowsAds = runCatching {
            UserMessagingPlatform.getConsentInformation(app).canRequestAds()
        }.getOrDefault(false)
        val allowed = AdMobEligibilityPolicy.shouldRequestAds(
            isPro = false,
            consentAllowsAds = consentAllowsAds
        )
        if (!allowed) mutableState.value = mutableState.value.copy(adsReady = false)
        return allowed
    }

    /** Only successful manual scans with no confirmed threats may show an interstitial. */
    suspend fun showInterstitialAfterManualScan(
        activity: Activity,
        manualScanCompleted: Boolean,
        hasConfirmedThreats: Boolean
    ) {
        if (activity.isFinishing || activity.isDestroyed || !canRequestAdsNow()) return
        if (!AdMobEligibilityPolicy.shouldShowInterstitial(
                isPro = false,
                consentAllowsAds = true,
                manualScanCompleted = manualScanCompleted,
                hasConfirmedThreats = hasConfirmedThreats
            )) return

        val ad = runCatching { InterstitialAdPreloader.pollAd(interstitialUnitId) }.getOrNull() ?: return
        // Check Pro again after polling and immediately before displaying full-screen content.
        if (!canRequestAdsNow() || hasConfirmedThreats || activity.isFinishing || activity.isDestroyed) return
        runCatching { ad.show(activity) }
    }

    suspend fun showPrivacyOptions(activity: Activity) {
        if (app.isProForAdMob() || activity.isFinishing || activity.isDestroyed) return
        val consent = UserMessagingPlatform.getConsentInformation(app)
        if (consent.privacyOptionsRequirementStatus !=
            ConsentInformation.PrivacyOptionsRequirementStatus.REQUIRED) return
        suspendCancellableCoroutine<Unit> { continuation ->
            runCatching {
                UserMessagingPlatform.showPrivacyOptionsForm(activity) {
                    if (continuation.isActive) continuation.resume(Unit)
                }
            }.onFailure {
                if (continuation.isActive) continuation.resume(Unit)
            }
        }
        refresh(activity)
    }

    /** A successful Pro grant immediately removes ads and destroys preloaded interstitials. */
    fun disableForPro() = disableForProInternal()

    private fun disableForProInternal() {
        if (interstitialPreloaderStarted) {
            runCatching { InterstitialAdPreloader.destroy(interstitialUnitId) }
            interstitialPreloaderStarted = false
        }
        mutableState.value = AdMobUiState(isPro = true, adsReady = false)
    }

    companion object {
        const val BANNER_UNIT_ID = "ca-app-pub-4783826505860771/4710308648"
        const val INTERSTITIAL_UNIT_ID = "ca-app-pub-4783826505860771/9523651625"
        const val TEST_BANNER_UNIT_ID = "/21775744923/example/adaptive-banner"
        const val TEST_INTERSTITIAL_UNIT_ID = "/21775744923/example/interstitial"
    }
}

/** Pure policy rules are unit-tested so a refactor cannot bypass Pro or consent. */
internal object AdMobEligibilityPolicy {
    fun shouldRequestAds(isPro: Boolean, consentAllowsAds: Boolean): Boolean =
        !isPro && consentAllowsAds

    fun shouldShowInterstitial(
        isPro: Boolean,
        consentAllowsAds: Boolean,
        manualScanCompleted: Boolean,
        hasConfirmedThreats: Boolean
    ): Boolean = shouldRequestAds(isPro, consentAllowsAds) &&
        manualScanCompleted && !hasConfirmedThreats
}
