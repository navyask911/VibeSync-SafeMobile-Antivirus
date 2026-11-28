package com.vibesync.antivirus.engine.ml

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
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
    fun corruptedApkReturnsExplicitFailureAndIsNotScored() = runBlocking {
        val apk = File.createTempFile("invalid-apk-", ".apk", context.cacheDir)
        try {
            apk.writeText("not a zip or apk")
            val extraction = DrebinFeatureExtractor(context).extractFeaturesAsync(apk)
            assertTrue(extraction is com.vibesync.antivirus.core.engine.DrebinApkExtractor.Outcome.Unscannable)
            assertEquals(
                com.vibesync.antivirus.core.engine.DrebinApkExtractor.Reason.APK_INVALID,
                (extraction as com.vibesync.antivirus.core.engine.DrebinApkExtractor.Outcome.Unscannable).reason
            )
            assertNull("Failed extraction must never be passed to inference.",
                TfliteInferenceEngine(context).runInference(extraction))
        } finally {
            apk.delete()
        }
    }

    @Test
    fun inferenceReturnsProbabilityFor215BinaryFeatures() = runBlocking {
        val probability = TfliteInferenceEngine(context).runInference(FloatArray(215))
        assertNotNull("The SHA-pinned model asset must be downloaded by the Gradle ML bridge.", probability)
        assertTrue(probability!! in 0.0f..1.0f)
        assertTrue(TfliteInferenceEngine.MODEL_REPORTED_THRESHOLD == 0.5f)
    }

    @Test
    fun inferenceRejectsIncorrectInputWidth() = runBlocking {
        assertNull(TfliteInferenceEngine(context).runInference(FloatArray(32)))
    }
}
