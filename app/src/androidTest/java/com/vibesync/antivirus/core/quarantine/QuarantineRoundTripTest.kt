package com.vibesync.antivirus.core.quarantine

import android.content.Context
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.core.crypto.HashCalculator
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class QuarantineRoundTripTest {
    @Test fun quarantineCreatesAuthenticatedEncryptedCopyAndRestoresExactBytes() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val manager = LocalQuarantineManager(context)
        val payload = ("SafeMobile test-only quarantine payload\u0000".repeat(256)).toByteArray(Charsets.UTF_8)
        val source = File(context.cacheDir, "quarantine-roundtrip-" + UUID.randomUUID() + ".bin")
        source.writeBytes(payload)
        var vault: File? = null
        val destination = Uri.parse("content://com.vibesync.antivirus.test.roundtrip/output-" + UUID.randomUUID())
        try {
            val sha256 = HashCalculator().calculate(source).sha256
            val outcome = manager.quarantineFile(source, sha256, removeOriginalAfterVerified = false)
            vault = outcome.privateCopy
            assertTrue(manager.isEncrypted(outcome.privateCopy))
            assertFalse(outcome.originalRemoved)
            assertTrue(source.exists())
            assertEquals(payload.size.toLong(), manager.restoreToUri(outcome.privateCopy, destination))
            val restored = context.contentResolver.openInputStream(destination)?.use { it.readBytes() }
                ?: throw AssertionError("The restored content provider stream was unavailable.")
            assertArrayEquals(payload, restored)
        } finally {
            vault?.let { manager.deleteQuarantinedFile(it) }
            source.delete()
            context.contentResolver.delete(destination, null, null)
        }
    }
}
