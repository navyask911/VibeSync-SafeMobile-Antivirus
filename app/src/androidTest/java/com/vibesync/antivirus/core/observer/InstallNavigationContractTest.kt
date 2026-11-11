package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.core.posture.PostureAccess
import com.vibesync.antivirus.core.posture.PostureFinding
import com.vibesync.antivirus.core.posture.PostureSettingsLinks
import org.junit.Assert.*
import com.vibesync.antivirus.core.observer.NotificationDeepLinkContract
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class InstallNavigationContractTest {

    @Test fun notificationTapIntentCarriesTypedPayloadAndUniqueEventIdentity() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val first = NotificationDeepLinkContract.intent(
            context, NotificationDeepLinkContract.TYPE_DOWNLOAD_MALICIOUS,
            "content://com.android.externalstorage.documents/document/primary%3ADownload%2Fsample.apk", "incident-one"
        )
        val second = NotificationDeepLinkContract.intent(
            context, NotificationDeepLinkContract.TYPE_DOWNLOAD_REVIEW,
            "content://com.android.externalstorage.documents/document/primary%3ADownload%2Freview.apk", "incident-two"
        )
        assertEquals("DOWNLOAD_MALICIOUS",
            first.getStringExtra(NotificationDeepLinkContract.EXTRA_NOTIFICATION_TYPE))
        assertEquals("incident-one", first.getStringExtra(NotificationDeepLinkContract.EXTRA_LOG_ID))
        assertTrue(first.getStringExtra(NotificationDeepLinkContract.EXTRA_FILE_URI).orEmpty().startsWith("content://"))
        assertNotEquals(first.data, second.data)
        assertEquals("incident-two", NotificationDeepLinkContract.fromIntent(second)?.logId)
    }

    @Test fun packageUrisAlwaysReferToTheInstalledPackageRegardlessOfInstaller() {
        assertEquals("com.example.fixture", PackageInstallReceiver.packageFrom(Uri.parse("package:com.example.fixture")))
        assertEquals("com.example.fixture", PackageInstallReceiver.packageFrom(Uri.parse("package://com.example.fixture")))
        assertNull(PackageInstallReceiver.packageFrom(Uri.parse("content://com.whatsapp/fixture.apk")))
        assertNull(PackageInstallReceiver.packageFrom(Uri.parse("package:invalid-Siren-Test")))
        assertNull(PackageInstallReceiver.packageFrom(null))
    }

    @Test fun overlayIntentUsesEachFlaggedPackageWithNewTaskBeforeCategoryFallback() {
        for (name in listOf("example.first", "example.second")) {
            val first = PostureSettingsLinks.candidates(PostureFinding(PostureAccess.OVERLAY, name, name)).first()
            assertEquals(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, first.action)
            assertEquals("package:$name", first.dataString)
            assertTrue(first.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
        }
    }
}
