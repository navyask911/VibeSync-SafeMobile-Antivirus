package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.tensorflow.lite.Interpreter

@RunWith(AndroidJUnit4::class)
class MachineLearningScannerTest {
    @Test fun downloadedResearchModelHas215InputsButIsNotProductionActivated() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // Gradle downloads the immutable ML Repo release before preBuild.
        // Historical Drebin holdout is research only; it is not enabled in production risk scoring.
        val scanner = MachineLearningScanner(context)
        assertFalse(scanner.isAvailable())
        assertTrue(scanner.isResearchCandidateAvailable())

        val model = context.assets.open("model.tflite").use { it.readBytes() }
        assertEquals(18_584, model.size)
        assertEquals(
            "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061",
            MessageDigest.getInstance("SHA-256").digest(model)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        )
        assertTrue(String(model, 4, 4, Charsets.US_ASCII) == "TFL3")
        val input = ByteBuffer.allocateDirect(model.size).order(ByteOrder.nativeOrder())
        input.put(model)
        input.rewind()
        Interpreter(input, Interpreter.Options().setNumThreads(1)).use { interpreter ->
            interpreter.allocateTensors()
            assertArrayEquals(intArrayOf(1, 215), interpreter.getInputTensor(0).shape())
            assertArrayEquals(intArrayOf(1, 1), interpreter.getOutputTensor(0).shape())
            val output = Array(1) { FloatArray(1) }
            interpreter.run(arrayOf(FloatArray(215)), output)
            assertTrue(output[0][0].isFinite())
        }
    }

    @Test fun aStagedResearchCandidateCannotEnableProductionClassification() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val folder = File(context.filesDir, "ml-research-candidates")
        assertTrue(folder.isDirectory || folder.mkdirs())
        val file = File(folder, "model.tflite")
        // A private copy cannot switch the source-pinned, production-disabled metadata gate.
        val model = context.assets.open("model.tflite").use { it.readBytes() }
        file.writeBytes(model)
        try {
            assertFalse(MachineLearningScanner(context).isAvailable())
            assertTrue(MachineLearningScanner(context).isResearchCandidateAvailable())
        } finally {
            file.delete()
        }
    }
}
