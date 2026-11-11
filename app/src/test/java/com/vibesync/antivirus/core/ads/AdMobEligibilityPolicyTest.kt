package com.vibesync.antivirus.core.ads

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AdMobEligibilityPolicyTest {
    @Test fun activeProNeverRequestsAdsEvenWithConsent() {
        assertFalse(AdMobEligibilityPolicy.shouldRequestAds(isPro = true, consentAllowsAds = true))
    }

    @Test fun freeTierRequiresConsentBeforeAds() {
        assertFalse(AdMobEligibilityPolicy.shouldRequestAds(isPro = false, consentAllowsAds = false))
        assertTrue(AdMobEligibilityPolicy.shouldRequestAds(isPro = false, consentAllowsAds = true))
    }

    @Test fun interstitialRequiresManualSuccessAndNoConfirmedThreats() {
        assertTrue(AdMobEligibilityPolicy.shouldShowInterstitial(
            isPro = false, consentAllowsAds = true,
            manualScanCompleted = true, hasConfirmedThreats = false
        ))
        assertFalse(AdMobEligibilityPolicy.shouldShowInterstitial(
            isPro = false, consentAllowsAds = true,
            manualScanCompleted = false, hasConfirmedThreats = false
        ))
        assertFalse(AdMobEligibilityPolicy.shouldShowInterstitial(
            isPro = false, consentAllowsAds = true,
            manualScanCompleted = true, hasConfirmedThreats = true
        ))
        assertFalse(AdMobEligibilityPolicy.shouldShowInterstitial(
            isPro = true, consentAllowsAds = true,
            manualScanCompleted = true, hasConfirmedThreats = false
        ))
    }
}
