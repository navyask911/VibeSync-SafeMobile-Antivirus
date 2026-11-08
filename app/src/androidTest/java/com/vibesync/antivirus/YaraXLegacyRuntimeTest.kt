package com.vibesync.antivirus

import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import com.vibesync.antivirus.core.engine.yara.YaraRuleManager
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Executes native YARA-X on Android 9 to cover the Wasmtime Pulley fallback.
 * The scan deliberately goes through Compiler.build and Scanner.scanBytes, not
 * just JNI loading or native library compilation.
 */
class YaraXLegacyRuntimeTest {

    @Test
    fun yaraXCompilesAndScansOnAndroid9WithoutCraneliftJit() = runBlocking {
        assumeTrue(
            "The Android 9 interpreter regression test runs on API 28 only.",
            Build.VERSION.SDK_INT == 28
        )

        val manager = YaraRuleManager(
            InstrumentationRegistry.getInstrumentation().targetContext
        )
        try {
            val response = manager.scanBytes("SafeMobile Android 9 interpreter smoke test".toByteArray())
            val json = JSONObject(response)
            assertTrue("YARA-X response must include the matches array.", json.has("matches"))
            assertTrue("YARA-X response must include the non-matching rules array.", json.has("nonMatching"))
        } finally {
            manager.close()
        }
    }
}
