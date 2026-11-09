package com.vibesync.antivirus.presentation

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
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

/** Fixed-height banner. Pro entitlement and UMP consent are rechecked immediately before load. */
@Composable
internal fun AdMobBanner(manager: AdMobManager) {
    val context = LocalContext.current
    val showLabel = LocalConfiguration.current.screenWidthDp >= 360
    val adView = remember(context) { AdView(context) }
    var loaded by remember(adView) { mutableStateOf(false) }

    LaunchedEffect(adView, manager) {
        loaded = false
        if (!manager.canRequestAdsNow()) return@LaunchedEffect
        runCatching {
            val request = BannerAdRequest.Builder(manager.bannerUnitId, AdSize.BANNER).build()
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
        Surface(Modifier.fillMaxWidth().height(56.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
            Row(
                modifier = Modifier.fillMaxSize(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center
            ) {
                if (showLabel) Text(
                    stringResource(R.string.ads_label),
                    modifier = Modifier.width(40.dp),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    softWrap = false,
                    overflow = TextOverflow.Clip
                )
                AndroidView(factory = { adView }, modifier = Modifier.width(320.dp).height(50.dp), update = {})
            }
        }
    }
}
