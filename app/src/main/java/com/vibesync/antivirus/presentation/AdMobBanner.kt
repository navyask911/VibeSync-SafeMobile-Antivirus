package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.wrapContentHeight
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.google.android.libraries.ads.mobile.sdk.banner.AdSize
import com.google.android.libraries.ads.mobile.sdk.banner.AdView
import com.google.android.libraries.ads.mobile.sdk.banner.BannerAd
import com.google.android.libraries.ads.mobile.sdk.banner.BannerAdRequest
import com.google.android.libraries.ads.mobile.sdk.common.AdLoadCallback
import com.google.android.libraries.ads.mobile.sdk.common.LoadAdError
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.ads.AdMobManager

/** Home-only adaptive banner. Re-checks Pro entitlement and UMP consent immediately before load. */
@Composable
internal fun AdMobBanner(manager: AdMobManager) {
    val context = LocalContext.current
    val widthDp = LocalConfiguration.current.screenWidthDp.coerceAtLeast(1)
    val adView = remember(context, widthDp) { AdView(context) }
    var loaded by remember(adView) { mutableStateOf(false) }

    LaunchedEffect(adView, manager, widthDp) {
        loaded = false
        if (!manager.canRequestAdsNow()) return@LaunchedEffect
        runCatching {
            val size = AdSize.getLargeAnchoredAdaptiveBannerAdSize(context, widthDp)
            val request = BannerAdRequest.Builder(manager.bannerUnitId, size).build()
            adView.loadAd(request, object : AdLoadCallback<BannerAd> {
                override fun onAdLoaded(ad: BannerAd) { loaded = true }
                override fun onAdFailedToLoad(adError: LoadAdError) { loaded = false }
            })
        }.onFailure { loaded = false }
    }

    DisposableEffect(adView) {
        onDispose { runCatching { adView.destroy() } }
    }

    if (loaded) {
        Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                stringResource(R.string.ads_label),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            AndroidView(
                factory = { adView },
                modifier = Modifier.fillMaxWidth().wrapContentHeight(),
                update = {}
            )
        }
    }
}
