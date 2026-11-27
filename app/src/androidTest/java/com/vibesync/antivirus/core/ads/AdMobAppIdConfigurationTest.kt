package com.vibesync.antivirus.core.ads

import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.R
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AdMobAppIdConfigurationTest {
    @Test
    fun manifestAndRuntimeUseTheApprovedNonTranslatableAppIdResource() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appId = context.getString(R.string.admob_app_id)

        assertEquals("ca-app-pub-4783826505860771~3262295335", appId)

        val applicationInfo = context.packageManager.getApplicationInfo(
            context.packageName,
            PackageManager.GET_META_DATA
        )
        assertEquals(
            appId,
            applicationInfo.metaData?.getString("com.google.android.gms.ads.APPLICATION_ID")
        )
    }
}
