package com.vibesync.antivirus.engine.ml

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OfflineMlLayerTest {
    private val context: Context
        get() = ApplicationProvider.getApplicationContext()

    @Test
    fun corruptedApkReturnsZeroed215FeatureVector() = runBlocking {
        val apk = File.createTempFile("invalid-apk-", ".apk", context.cacheDir)
        try {
            apk.writeText("not a zip or apk")
            val features = DrebinFeatureExtractor(context).extractFeaturesAsync(apk)
            assertArrayEquals(FloatArray(215), features, 0.0f)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun inferenceReturnsProbabilityFor215BinaryFeatures() = runBlocking {
        val probability = TfliteInferenceEngine(context).runInference(FloatArray(215))
        assertNotNull("The SHA-pinned model asset must be downloaded by the Gradle ML bridge.", probability)
        assertTrue(probability!! in 0.0f..1.0f)
        assertTrue(TfliteInferenceEngine.MALWARE_THRESHOLD == 0.5f)
    }

    @Test
    fun inferenceRejectsIncorrectInputWidth() = runBlocking {
        assertNull(TfliteInferenceEngine(context).runInference(FloatArray(32)))
    }
}
