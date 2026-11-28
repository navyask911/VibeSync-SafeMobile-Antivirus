package com.vibesync.antivirus.validation

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.os.Debug
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.core.engine.DrebinApkExtractor
import com.vibesync.antivirus.core.engine.DrebinFeatureContract
import com.vibesync.antivirus.engine.ml.TfliteInferenceEngine
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.math.ceil
import kotlin.math.sqrt
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.tensorflow.lite.DataType
import org.tensorflow.lite.Interpreter

/**
 * Private device-side parity and timing data collector.
 * Push APKs into getExternalFilesDir("drebin-validation")/apks before running.
 * Supply -e appCommit=<exact 40-character source SHA>.
 * Output contains sample vectors and stays in app-scoped external storage.
 */
@RunWith(AndroidJUnit4::class)
class DrebinDeviceValidationHarnessTest {
    @Test
    fun exportPairedVectorsAndMeasureInference() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val appCommit = InstrumentationRegistry.getArguments().getString("appCommit").orEmpty()
        require(appCommit.matches(Regex("[0-9a-fA-F]{40}"))) {
            "Pass the exact Android source SHA using -e appCommit=<sha>"
        }

        val schemaBytes = context.assets.open("feature_schema.json").use { it.readBytes() }
        val schemaSha = sha256(schemaBytes)
        require(schemaSha == EXPECTED_SCHEMA_SHA256) { "Frozen schema SHA-256 mismatch" }
        val schema = DrebinFeatureContract.loadSchema(context.assets)
            ?: error("Packaged 215-feature schema could not be loaded")
        assertEquals(215, schema.size)

        val root = File(context.getExternalFilesDir("drebin-validation"), ".")
        val apkDirectory = File(root, "apks")
        check(apkDirectory.mkdirs() || apkDirectory.isDirectory)
        val apkFiles = apkDirectory.listFiles().orEmpty()
            .filter { it.isFile && it.extension.equals("apk", ignoreCase = true) }
            .sortedBy { it.name }.take(MAX_APK_SAMPLES)

        val modelBytes = context.assets.open("model.tflite").use { it.readBytes() }
        val modelSha = sha256(modelBytes)
        require(modelBytes.size == EXPECTED_MODEL_BYTES && modelSha == EXPECTED_MODEL_SHA256) {
            "Packaged model is not the approved v1.0.1-model asset"
        }
        require(String(modelBytes, 4, 4, Charsets.US_ASCII) == "TFL3")

        val assetReadHashNs = mutableListOf<Long>()
        val interpreterInitNs = mutableListOf<Long>()
        repeat(COLD_INTERPRETER_REPETITIONS) {
            val readStart = SystemClock.elapsedRealtimeNanos()
            val bytes = context.assets.open("model.tflite").use { it.readBytes() }
            check(sha256(bytes) == EXPECTED_MODEL_SHA256)
            assetReadHashNs += SystemClock.elapsedRealtimeNanos() - readStart

            val initStart = SystemClock.elapsedRealtimeNanos()
            createInterpreter(bytes).use(::validateTensorContract)
            interpreterInitNs += SystemClock.elapsedRealtimeNanos() - initStart
        }

        val retained = createInterpreter(modelBytes)
        validateTensorContract(retained)
        val input = arrayOf(FloatArray(215))
        repeat(minOf(50, REUSED_INTERPRETER_ITERATIONS)) { invoke(retained, input) }
        val invokeOnlyNs = mutableListOf<Long>()
        repeat(REUSED_INTERPRETER_ITERATIONS) {
            val start = SystemClock.elapsedRealtimeNanos()
            val score = invoke(retained, input)
            check(score.isFinite() && score in 0.0f..1.0f)
            invokeOnlyNs += SystemClock.elapsedRealtimeNanos() - start
        }
        retained.close()

        val memoryBefore = memorySnapshot(context)
        val engine = TfliteInferenceEngine(context)
        repeat(PRODUCTION_WARMUP_CALLS) {
            check(engine.runInference(FloatArray(215)) != null) { "Production inference warmup failed" }
        }
        val productionCallsNs = mutableListOf<Long>()
        var nullProductionScores = 0
        repeat(PRODUCTION_PATH_ITERATIONS) {
            val start = SystemClock.elapsedRealtimeNanos()
            val score = engine.runInference(FloatArray(215))
            productionCallsNs += SystemClock.elapsedRealtimeNanos() - start
            if (score == null) nullProductionScores++
        }
        val memoryAfterProduction = memorySnapshot(context)

        val extractionNs = mutableListOf<Long>()
        val extractAndInferNs = mutableListOf<Long>()
        val apkResults = JSONArray()
        var featureCount = 0
        var unscannableCount = 0
        var nullApkScores = 0
        for (apk in apkFiles) {
            val apkSha = sha256(apk)
            val record = JSONObject()
                .put("sample_id", apkSha.take(16))
                .put("apk_sha256", apkSha)
                .put("android_status", "UNSCANNABLE")
            val pipelineStart = SystemClock.elapsedRealtimeNanos()
            val extractStart = SystemClock.elapsedRealtimeNanos()
            when (val result = DrebinApkExtractor.extract(apk, schema)) {
                is DrebinApkExtractor.Outcome.Features -> {
                    extractionNs += SystemClock.elapsedRealtimeNanos() - extractStart
                    featureCount++
                    require(result.vector.size == 215 && result.vector.all { it == 0.0f || it == 1.0f })
                    record.put("android_status", "FEATURES")
                    record.put("android_vector", JSONArray().also { vector ->
                        result.vector.forEach { vector.put(it.toInt()) }
                    })
                    val score = engine.runInference(result.vector)
                    if (score == null) nullApkScores++
                    record.put("android_probability", score ?: JSONObject.NULL)
                    record.put("android_reason", JSONObject.NULL)
                }
                is DrebinApkExtractor.Outcome.Unscannable -> {
                    extractionNs += SystemClock.elapsedRealtimeNanos() - extractStart
                    unscannableCount++
                    record.put("android_reason", result.reason.name)
                    record.put("android_vector", JSONObject.NULL)
                    record.put("android_probability", JSONObject.NULL)
                }
            }
            extractAndInferNs += SystemClock.elapsedRealtimeNanos() - pipelineStart
            apkResults.put(record)
        }
        val memoryAfterCorpus = memorySnapshot(context)

        val output = JSONObject()
            .put("report_version", 1)
            .put("schema_sha256", schemaSha)
            .put("model_sha256", modelSha)
            .put("model_bytes", modelBytes.size)
            .put("android_app", JSONObject()
                .put("commit", appCommit.lowercase())
                .put("version_name", BuildConfig.VERSION_NAME)
                .put("version_code", BuildConfig.VERSION_CODE)
                .put("api_level", Build.VERSION.SDK_INT)
                .put("manufacturer", Build.MANUFACTURER)
                .put("model", Build.MODEL)
                .put("device", Build.DEVICE)
                .put("supported_abis", JSONArray(Build.SUPPORTED_ABIS.toList()))
                .put("processors", Runtime.getRuntime().availableProcessors()))
            .put("benchmark", JSONObject()
                .put("cold_asset_read_hash", summarize(assetReadHashNs))
                .put("cold_interpreter_create_allocate", summarize(interpreterInitNs))
                .put("reused_interpreter_invoke_only", summarize(invokeOnlyNs))
                .put("production_engine_new_interpreter_per_call", summarize(productionCallsNs))
                .put("production_null_results", nullProductionScores)
                .put("production_iterations", PRODUCTION_PATH_ITERATIONS)
                .put("reused_interpreter_iterations", REUSED_INTERPRETER_ITERATIONS)
                .put("memory_before_production", memoryBefore)
                .put("memory_after_production", memoryAfterProduction)
                .put("memory_after_apk_corpus", memoryAfterCorpus))
            .put("apk_corpus", JSONObject()
                .put("sample_count", apkFiles.size)
                .put("features_extracted", featureCount)
                .put("unscannable", unscannableCount)
                .put("null_inference_results", nullApkScores)
                .put("extraction_latency", summarize(extractionNs))
                .put("extract_plus_inference_latency", summarize(extractAndInferNs)))
            .put("apk_results", apkResults)
            .put("scope", "APK feature extraction plus ML inference; not full PackageScanner/YARA/hash scan")
            .put("private_data_warning", "Contains per-APK vectors; keep local and do not commit or publish samples")

        val outputDirectory = File(root, "results")
        check(outputDirectory.mkdirs() || outputDirectory.isDirectory)
        val outputFile = File(outputDirectory, "drebin-device-validation.json")
        outputFile.writeText(output.toString(2), Charsets.UTF_8)
        assertTrue("Production inference must return valid scores", nullProductionScores == 0)
        assertEquals(apkFiles.size, apkResults.length())
        android.util.Log.i(TAG, "Validation artifact written to ${outputFile.absolutePath}")
    }

    private fun createInterpreter(bytes: ByteArray): Interpreter {
        val buffer = ByteBuffer.allocateDirect(bytes.size).order(ByteOrder.nativeOrder())
        buffer.put(bytes)
        buffer.rewind()
        return Interpreter(buffer, Interpreter.Options().setNumThreads(1)).also {
            it.allocateTensors()
        }
    }

    private fun validateTensorContract(interpreter: Interpreter) {
        require(interpreter.inputTensorCount == 1 && interpreter.outputTensorCount == 1)
        val input = interpreter.getInputTensor(0)
        val output = interpreter.getOutputTensor(0)
        require(input.shape().contentEquals(intArrayOf(1, 215)) && input.dataType() == DataType.FLOAT32)
        require(output.shape().contentEquals(intArrayOf(1, 1)) && output.dataType() == DataType.FLOAT32)
    }

    private fun invoke(interpreter: Interpreter, input: Array<FloatArray>): Float {
        val output = Array(1) { FloatArray(1) }
        interpreter.run(input, output)
        return output[0][0]
    }

    private fun memorySnapshot(context: Context): JSONObject {
        val pss = Debug.MemoryInfo()
        Debug.getMemoryInfo(pss)
        val runtime = Runtime.getRuntime()
        val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val system = ActivityManager.MemoryInfo().also { manager.getMemoryInfo(it) }
        return JSONObject()
            .put("total_pss_kb", pss.totalPss)
            .put("native_pss_kb", pss.nativePss)
            .put("dalvik_pss_kb", pss.dalvikPss)
            .put("native_heap_allocated_bytes", Debug.getNativeHeapAllocatedSize())
            .put("java_heap_used_bytes", runtime.totalMemory() - runtime.freeMemory())
            .put("system_total_ram_bytes", system.totalMem)
            .put("system_available_ram_bytes", system.availMem)
    }

    private fun summarize(samplesNs: List<Long>): JSONObject {
        if (samplesNs.isEmpty()) return JSONObject().put("samples", 0)
        val sorted = samplesNs.sorted()
        val ms = sorted.map { it / 1_000_000.0 }
        val mean = ms.average()
        val variance = ms.sumOf { (it - mean) * (it - mean) } / ms.size
        fun p(p: Double): Double {
            val index = (ceil(p * sorted.size).toInt() - 1).coerceIn(0, sorted.lastIndex)
            return ms[index]
        }
        return JSONObject()
            .put("samples", sorted.size)
            .put("unit", "ms")
            .put("mean", mean)
            .put("stddev", sqrt(variance))
            .put("min", ms.first())
            .put("p50", p(0.50))
            .put("p95", p(0.95))
            .put("p99", p(0.99))
            .put("max", ms.last())
    }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    private companion object {
        const val TAG = "SafeMobileValidation"
        const val MAX_APK_SAMPLES = 100
        const val COLD_INTERPRETER_REPETITIONS = 10
        const val REUSED_INTERPRETER_ITERATIONS = 1_000
        const val PRODUCTION_WARMUP_CALLS = 5
        const val PRODUCTION_PATH_ITERATIONS = 30
        const val EXPECTED_MODEL_BYTES = 18_584
        const val EXPECTED_MODEL_SHA256 =
            "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"
        const val EXPECTED_SCHEMA_SHA256 =
            "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
    }
}
