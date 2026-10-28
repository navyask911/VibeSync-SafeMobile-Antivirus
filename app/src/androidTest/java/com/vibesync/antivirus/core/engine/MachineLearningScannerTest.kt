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
    @Test fun bundledDummyIsShapeCorrectButNeverActivated() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        // No untrained score can change a real scan result.
        assertFalse(MachineLearningScanner(context).isAvailable())
        val model = context.assets.open("malware_model.tflite").use { it.readBytes() }
        assertTrue(model.size < 50 * 1024 * 1024)
        assertTrue(model.size > 64)
        assertTrue(String(model, 4, 4, Charsets.US_ASCII) == "TFL3")
        val input = ByteBuffer.allocateDirect(model.size).order(ByteOrder.nativeOrder())
        input.put(model)
        input.rewind()
        Interpreter(input, Interpreter.Options().setNumThreads(1)).use { interpreter ->
            interpreter.allocateTensors()
            assertArrayEquals(intArrayOf(1, 32), interpreter.getInputTensor(0).shape())
            assertArrayEquals(intArrayOf(1, 1), interpreter.getOutputTensor(0).shape())
            val output = Array(1) { FloatArray(1) }
            interpreter.run(arrayOf(FloatArray(32)), output)
            assertTrue(output[0][0].isFinite())
        }
    }
}
