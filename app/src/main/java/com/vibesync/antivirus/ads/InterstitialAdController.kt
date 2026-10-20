package com.vibesync.antivirus.ads
import android.app.Activity
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.FullScreenContentCallback
import com.google.android.gms.ads.LoadAdError
import com.google.android.gms.ads.interstitial.InterstitialAd
import com.google.android.gms.ads.interstitial.InterstitialAdLoadCallback
import com.vibesync.antivirus.BuildConfig

/** Show only on completed scan transitions, capped at one ad per three completed sessions. */
class InterstitialAdController(private val activity: Activity, private val enabled: Boolean) {
 private var ad: InterstitialAd? = null
 private var loading = false
 fun load() {
  if (!enabled || loading || ad != null || activity.isFinishing) return
  loading = true
  InterstitialAd.load(activity, BuildConfig.INTERSTITIAL_AD_UNIT_ID, AdRequest.Builder().build(),
   object : InterstitialAdLoadCallback() {
    override fun onAdLoaded(loaded: InterstitialAd) { loading = false; ad = loaded }
    override fun onAdFailedToLoad(error: LoadAdError) { loading = false; ad = null }
   })
 }
 fun showAfterScan(completedScans: Int) {
  if (!enabled || completedScans <= 0 || completedScans % 3 != 0) return
  val loaded = ad ?: run { load(); return }
  ad = null
  loaded.fullScreenContentCallback = object : FullScreenContentCallback() {
   override fun onAdDismissedFullScreenContent() { load() }
   override fun onAdFailedToShowFullScreenContent(error: com.google.android.gms.ads.AdError) { load() }
  }
  loaded.show(activity)
 }
}
