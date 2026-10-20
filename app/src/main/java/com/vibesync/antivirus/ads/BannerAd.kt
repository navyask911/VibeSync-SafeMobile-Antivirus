package com.vibesync.antivirus.ads
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import com.google.android.gms.ads.AdRequest
import com.google.android.gms.ads.AdSize
import com.google.android.gms.ads.AdView
import com.vibesync.antivirus.BuildConfig

@Composable
fun BannerAd(modifier: Modifier = Modifier) {
 val context = LocalContext.current
 val widthDp = LocalConfiguration.current.screenWidthDp.coerceAtLeast(320)
 val view = remember(context, widthDp) {
  AdView(context).apply {
   adUnitId = BuildConfig.BANNER_AD_UNIT_ID
   setAdSize(AdSize.getCurrentOrientationAnchoredAdaptiveBannerAdSize(context, widthDp))
   loadAd(AdRequest.Builder().build())
  }
 }
 DisposableEffect(view) {
  onDispose {
   (view.parent as? android.view.ViewGroup)?.removeView(view)
   view.destroy()
  }
 }
 AndroidView(modifier = modifier.fillMaxWidth(), factory = { view })
}
