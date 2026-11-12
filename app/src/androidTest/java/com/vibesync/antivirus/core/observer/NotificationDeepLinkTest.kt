package com.vibesync.antivirus.core.observer

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NotificationDeepLinkTest {
    @Test
    fun readsExplicitNotificationPayloadWithoutDefaultingToHome() {
        val intent = Intent()
            .putExtra(NotificationDeepLink.EXTRA_NOTIFICATION_TYPE, "DOWNLOAD_MALICIOUS")
            .putExtra(NotificationDeepLink.EXTRA_FILE_URI, "content://downloads/document/41")
            .putExtra(NotificationDeepLink.EXTRA_LOG_ID, "event-41")
            .putExtra(NotificationDeepLink.EXTRA_FILE_NAME, "sample.apk")
            .putExtra(NotificationDeepLink.EXTRA_FILE_PATH, "/storage/emulated/0/Download/sample.apk")
            .putExtra(NotificationDeepLink.EXTRA_REASON, "local_sha256_match")
        val route = NotificationDeepLink.fromIntent(intent)
        assertEquals("DOWNLOAD_MALICIOUS", route?.notificationType)
        assertEquals("content://downloads/document/41", route?.fileUri)
        assertEquals("event-41", route?.logId)
        assertEquals("sample.apk", route?.fileName)
        assertEquals("/storage/emulated/0/Download/sample.apk", route?.filePath)
        assertEquals("local_sha256_match", route?.reason)
    }

    @Test
    fun ignoresIntentsWithoutAnExplicitNotificationType() {
        assertNull(NotificationDeepLink.fromIntent(Intent()))
    }
}
