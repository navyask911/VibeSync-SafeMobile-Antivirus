package com.vibesync.antivirus.core.observer

import android.app.NotificationManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FullScreenAlertAccessTest {
    @Test fun accessCheckUsesSystemStateAndSettingsTargetsOnlyThisApp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        if (Build.VERSION.SDK_INT >= 34) {
            assertEquals(context.getSystemService(NotificationManager::class.java).canUseFullScreenIntent(),
                FullScreenAlertAccess.isGranted(context))
            val intent = FullScreenAlertAccess.settingsIntent(context)!!
            assertEquals(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, intent.action)
            assertEquals("package:" + context.packageName, intent.data.toString())
        } else {
            assertTrue(FullScreenAlertAccess.isGranted(context))
            assertNull(FullScreenAlertAccess.settingsIntent(context))
        }
    }
}
