package com.vibesync.antivirus.core.quarantine

import android.content.Context
import android.net.Uri
import android.util.Log
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
import java.io.PrintWriter
import java.io.StringWriter
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class QuarantineRoundTripTest {
    private fun checkpoint(context: Context, message: String) {
        val diagnostic = File(context.filesDir, DIAGNOSTIC_FILE)
        diagnostic.appendText(message + "\n")
        Log.i(TAG, message)
    }

    @Test fun quarantineCreatesAuthenticatedEncryptedCopyAndRestoresExactBytes() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val diagnostic = File(context.filesDir, DIAGNOSTIC_FILE)
        diagnostic.delete()
        val manager = LocalQuarantineManager(context)
        val payload = ("SafeMobile test-only quarantine payload\u0000".repeat(256)).toByteArray(Charsets.UTF_8)
        val source = File(context.cacheDir, "quarantine-roundtrip-" + UUID.randomUUID() + ".bin")
        source.writeBytes(payload)
        var vault: File? = null
        val destination = Uri.parse("content://com.vibesync.antivirus.test.roundtrip/output-" + UUID.randomUUID())
        try {
            checkpoint(context, "STEP 1: source fixture created; bytes=" + payload.size)
            val sha256 = HashCalculator().calculate(source).sha256
            checkpoint(context, "STEP 2: source hash calculated=" + sha256)
            val outcome = manager.quarantineFile(source, sha256, removeOriginalAfterVerified = false)
            vault = outcome.privateCopy
            checkpoint(context, "STEP 3: encrypted quarantine copy created=" + outcome.privateCopy.name)
            assertTrue("quarantine copy must have the encrypted extension", manager.isEncrypted(outcome.privateCopy))
            assertFalse("source must remain until an explicit delete action", outcome.originalRemoved)
            assertTrue("source file should still exist", source.exists())
            checkpoint(context, "STEP 4: encryption and source-retention assertions passed")
            assertTrue("restore provider must be resolvable", context.packageManager.resolveContentProvider(
                "com.vibesync.antivirus.test.roundtrip", 0
            ) != null)
            checkpoint(context, "STEP 5: restore content provider resolved")
            val restoredBytes = manager.restoreToUri(outcome.privateCopy, destination)
            checkpoint(context, "STEP 6: restoreToUri completed; bytes=" + restoredBytes)
            assertEquals("restored byte count", payload.size.toLong(), restoredBytes)
            val restored = context.contentResolver.openInputStream(destination)?.use { it.readBytes() }
                ?: throw AssertionError("The restored content provider stream was unavailable.")
            checkpoint(context, "STEP 7: destination readback complete; bytes=" + restored.size)
            assertArrayEquals("restored bytes must exactly match the source", payload, restored)
            checkpoint(context, "PASS: encrypted quarantine round-trip verified")
        } catch (failure: Throwable) {
            val stack = StringWriter().also { writer -> failure.printStackTrace(PrintWriter(writer)) }.toString()
            runCatching { checkpoint(context, "FAIL: " + failure.javaClass.name + ": " + failure.message + "\n" + stack) }
            throw AssertionError("Quarantine round-trip diagnostics are in files/" + DIAGNOSTIC_FILE, failure)
        } finally {
            vault?.let { runCatching { manager.deleteQuarantinedFile(it) } }
            source.delete()
            runCatching { context.contentResolver.delete(destination, null, null) }
        }
    }

    companion object {
        private const val TAG = "SafeMobileQuarantineTest"
        private const val DIAGNOSTIC_FILE = "quarantine-roundtrip-diagnostics.txt"
    }
}
