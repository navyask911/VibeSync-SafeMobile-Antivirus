package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.tensorflow.lite.Interpreter

@RunWith(AndroidJUnit4::class)
class MachineLearningScannerTest {
    @Test fun bundledResearchModelHas215InputsButIsNotProductionActivated() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // Historical Drebin holdout is research only; not enabled in production risk scoring.
        assertFalse(MachineLearningScanner(context).isAvailable())
        assertTrue(MachineLearningScanner(context).isResearchCandidateAvailable())
        val model = context.assets.open("malware_model.tflite").use { it.readBytes() }
        assertTrue(model.size < 50 * 1024 * 1024)
        assertTrue(model.size > 64)
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
        val folder = java.io.File(context.filesDir, "ml-research-candidates")
        assertTrue(folder.isDirectory || folder.mkdirs())
        val file = java.io.File(folder, "malware_model.tflite")
        // A private downloaded file must not circumvent the trusted metadata gate.
        val model = context.assets.open("malware_model.tflite").use { it.readBytes() }
        file.writeBytes(model)
        try {
            context.getSharedPreferences("safe_mobile_ml_candidate", Context.MODE_PRIVATE)
                .edit().putString("candidate_version", "v1.0.0-model")
                .putString("candidate_sha256", "a".repeat(64))
                .putBoolean("production_active", false).commit()
            assertFalse(MachineLearningScanner(context).isAvailable())
        } finally {
            file.delete()
            context.getSharedPreferences("safe_mobile_ml_candidate", Context.MODE_PRIVATE)
                .edit().clear().commit()
        }
    }

}
