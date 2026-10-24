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

    @Test fun oldPlaintextAuditRowsRemainReadableDuringMigration() {
        val store = EncryptedHashStore(ApplicationProvider.getApplicationContext())
        assertEquals("com.example.legacy", store.revealPrivateText("com.example.legacy", "scan-label"))
    }
}
