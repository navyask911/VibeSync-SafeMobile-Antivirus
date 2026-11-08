package com.vibesync.antivirus

import android.content.Intent
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import com.vibesync.antivirus.core.engine.yara.YaraRuleManager
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/**
 * Launches the actual app and executes native YARA-X on Android 9 to cover
 * Wasmtime Pulley fallback. The scan goes through Compiler.build and
 * Scanner.scanBytes, not only JNI loading or native library compilation.
 */
class YaraXLegacyRuntimeTest {

    @Test
    fun appLaunchesAndYaraXCompilesAndScansOnAndroid9WithoutCraneliftJit() = runBlocking {
        assumeTrue(
            "The Android 9 interpreter regression test runs on API 28 only.",
            Build.VERSION.SDK_INT == 28
        )

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val activity = instrumentation.startActivitySync(
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        try {
            assertTrue(
                "MainActivity must reach a running state on Android 9.",
                !activity.isFinishing && !activity.isDestroyed
            )

            val manager = YaraRuleManager(context)
            try {
                val response = manager.scanBytes(
                    "SafeMobile Android 9 interpreter smoke test".toByteArray()
                )
                val json = JSONObject(response)
                assertTrue("YARA-X response must include the matches array.", json.has("matches"))
                assertTrue("YARA-X response must include the non-matching rules array.", json.has("nonMatching"))
            } finally {
                manager.close()
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}
