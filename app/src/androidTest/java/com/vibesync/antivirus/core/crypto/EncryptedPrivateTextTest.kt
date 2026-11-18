package com.vibesync.antivirus.core.crypto

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncryptedPrivateTextTest {
    @Test fun sensitiveLabelsAndPathsAreEncryptedAndFieldBound() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = EncryptedHashStore(context)
        val original = "/storage/emulated/0/Download/private-document.apk"
        val cipher = store.protectPrivateText(original, "scan-label")
        assertNotEquals(original, cipher)
        assertTrue(cipher.startsWith("sm-enc-v1:scan-label:"))
        assertEquals(original, store.revealPrivateText(cipher, "scan-label"))
        assertTrue(runCatching { store.revealPrivateText(cipher, "incident-path") }.isFailure)
    }

    @Test fun scanSessionMetadataPurposesAreEncryptedAndRoundTrip() {
        val store = EncryptedHashStore(ApplicationProvider.getApplicationContext())
        val longUri = "content://com.example.provider/tree/" + "segment/".repeat(180)

        val samples = linkedMapOf(
            "scan-progress-path" to "/data/app/com.example.target/base.apk",
            "scan-progress-reasons" to "manifest risk\\npermission risk",
            "scan-progress-uri" to longUri,
            "scan-resume-uri" to longUri
        )
        samples.forEach { (purpose, value) ->
            val encrypted = store.protectPrivateText(value, purpose)
            assertNotEquals(value, encrypted)
            assertTrue(encrypted.startsWith("sm-enc-v1:$purpose:"))
            assertEquals(value, store.revealPrivateText(encrypted, purpose))
        }
    }

    @Test fun oldPlaintextAuditRowsRemainReadableDuringMigration() {
        val store = EncryptedHashStore(ApplicationProvider.getApplicationContext())
        assertEquals("com.example.legacy", store.revealPrivateText("com.example.legacy", "scan-label"))
    }
}
