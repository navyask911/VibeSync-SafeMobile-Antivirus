package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DrebinSchemaInstrumentedTest {
    @Test fun bundledSchemaHasExact215FeaturesAndDemoIsStillDisabled() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val names = DrebinFeatureContract.loadSchema(app.assets)
        assertNotNull(names)
        assertEquals(215, names!!.size)
        assertEquals("transact", names[0])
        assertEquals("SEND_SMS", names[6])
        assertEquals("WRITE_SECURE_SETTINGS", names[214])
        assertFalse(MachineLearningScanner(app).isAvailable())
    }

    @Test fun malformedApkReportsUnscannableAndNeverCrashes() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val file = File.createTempFile("unscannable-", ".apk", app.cacheDir)
        try {
            file.writeBytes(byteArrayOf(0x50, 0x4b, 0x03, 0x04))
            val result = MachineLearningScanner(app).extractFeatureVector(file)
            assertTrue(result is DrebinApkExtractor.Outcome.Unscannable)
        } finally {
            file.delete()
        }
    }
}
