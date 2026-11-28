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
import java.io.ByteArrayOutputStream
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
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

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
        val contractFixtureSummary = verifyFeatureContractFixtures(schema)

        val root = File(
            requireNotNull(context.getExternalFilesDir("drebin-validation")) {
                "App-scoped external storage is unavailable"
            }, "."
        )
        val apkDirectory = File(root, "apks")
        check(apkDirectory.mkdirs() || apkDirectory.isDirectory)
        val apkParserFixtureSummary = verifyApkParserFixtures(root, schema)
        val selfApk = File(context.applicationInfo.sourceDir)

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
        val memoryMilestones = JSONObject()
        var nullProductionScores = 0
        repeat(PRODUCTION_PATH_ITERATIONS) { index ->
            val start = SystemClock.elapsedRealtimeNanos()
            val score = engine.runInference(FloatArray(215))
            productionCallsNs += SystemClock.elapsedRealtimeNanos() - start
            if (score == null) nullProductionScores++
            val completed = index + 1
            if (completed in MEMORY_MILESTONES) {
                memoryMilestones.put(completed.toString(), memorySnapshot(context))
            }
        }
        val memoryAfterProduction = memorySnapshot(context)
        val selfApkProbe = when (val result = DrebinApkExtractor.extract(selfApk, schema)) {
            is DrebinApkExtractor.Outcome.Features ->
                JSONObject().put("status", "FEATURES").put("active_feature_count", result.vector.count { it == 1.0f })
            is DrebinApkExtractor.Outcome.Unscannable ->
                JSONObject().put("status", "UNSCANNABLE").put("reason", result.reason.name)
        }.put("apk_sha256", sha256(selfApk))

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
                .put("memory_at_production_milestones", memoryMilestones)
                .put("memory_after_production", memoryAfterProduction)
                .put("memory_after_apk_corpus", memoryAfterCorpus))
            .put("apk_corpus", JSONObject()
                .put("sample_count", apkFiles.size)
                .put("features_extracted", featureCount)
                .put("unscannable", unscannableCount)
                .put("null_inference_results", nullApkScores)
                .put("extraction_latency", summarize(extractionNs))
                .put("extract_plus_inference_latency", summarize(extractAndInferNs)))
            .put("contract_fixtures", contractFixtureSummary)
            .put("apk_parser_fixtures", apkParserFixtureSummary)
            .put("installed_app_base_apk_probe", selfApkProbe)
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

    private fun verifyFeatureContractFixtures(schema: List<String>): JSONObject {
        val empty = DrebinFeatureContract.Observed(
            permissions = emptySet(), actions = emptySet(), classes = emptySet(),
            calls = emptySet(), callbacks = emptySet(), literals = emptySet(),
        )
        val zeroVector = DrebinFeatureContract.vector(schema, empty)
        assertEquals(215, zeroVector.size)
        assertTrue("Empty observation must produce an all-zero vector", zeroVector.all { it == 0.0f })

        var activatedSlots = 0
        for (index in schema.indices) {
            val observed = fixtureObservation(schema[index])
            val actual = DrebinFeatureContract.vector(schema, observed)
            val repeat = DrebinFeatureContract.vector(schema, observed)
            assertEquals("Positive fixture failed at feature index $index (" + schema[index] + ")", 1f, actual[index], 0f)
            assertEquals("Feature fixture is non-deterministic at index $index", actual.toList(), repeat.toList())
            activatedSlots += actual.count { it == 1.0f }
        }

        val runtimeExecIndex = schema.indexOf("Runtime.exec")
        check(runtimeExecIndex >= 0)
        val unrelatedOwnerCall = DrebinFeatureContract.Observed(
            permissions = emptySet(), actions = emptySet(), classes = emptySet(),
            calls = setOf("Lother/Runtime;" to "exec"),
            callbacks = emptySet(), literals = emptySet(),
        )
        val simpleOwnerCollisionObserved =
            DrebinFeatureContract.vector(schema, unrelatedOwnerCall)[runtimeExecIndex] == 1.0f

        return JSONObject()
            .put("schema_feature_count", schema.size)
            .put("positive_fixtures_passed", schema.size)
            .put("empty_vector_negative_fixture_passed", true)
            .put("determinism_checks_passed", schema.size)
            .put("positive_fixture_activated_slots_total", activatedSlots)
            .put("unrelated_owner_activates_Runtime_exec_feature", simpleOwnerCollisionObserved)
            .put("fixture_scope", "direct Kotlin DrebinFeatureContract observation mapping; not APK parser coverage")
    }

    private fun fixtureObservation(feature: String): DrebinFeatureContract.Observed {
        val permissions = mutableSetOf<String>()
        val actions = mutableSetOf<String>()
        val classes = mutableSetOf<String>()
        val calls = mutableSetOf<Pair<String, String>>()
        val callbacks = mutableSetOf<String>()
        val literals = mutableSetOf<String>()

        when {
            feature.isNotBlank() && feature.all { it.isUpperCase() || it.isDigit() || it == '_' } ->
                permissions.add("android.permission.$feature")
            "intent.action." in feature ->
                actions.add(if (feature == "intent.action.RUN") "android.intent.action.RUN" else feature)
            feature in CLASS_FEATURE_NAMES ->
                classes.add(feature)
            feature in COMMAND_NAMES || feature.startsWith("/system/") ->
                literals.add(feature)
            feature in CALLBACK_NAMES ->
                callbacks.add(feature)
            else -> {
                val normalized = if (
                    feature.startsWith("Ljava.") || feature.startsWith("Ljavax.") ||
                    feature.startsWith("Landroid.")
                ) feature.drop(1) else feature
                val separator = normalized.lastIndexOf('.')
                if (separator > 0) {
                    calls.add(normalized.substring(0, separator) to normalized.substring(separator + 1))
                } else {
                    calls.add("Lfixture/Only;" to feature)
                }
            }
        }
        return DrebinFeatureContract.Observed(
            permissions = permissions, actions = actions, classes = classes,
            calls = calls, callbacks = callbacks, literals = literals,
        )
    }

    private suspend fun verifyApkParserFixtures(
        root: File,
        schema: List<String>,
    ): JSONObject {
        val manifest = createBinaryManifestFixture()
        val parsed = requireNotNull(com.vibesync.antivirus.core.engine.BinaryAndroidManifest.parse(manifest)) {
            "Synthetic harmless binary AndroidManifest fixture did not parse"
        }
        assertEquals(setOf("android.permission.INTERNET"), parsed.permissions)
        assertEquals(setOf("android.intent.action.BOOT_COMPLETED"), parsed.actions)

        val missingDex = File(root, "fixture-manifest-without-dex.apk")
        writeZipFixture(missingDex, manifest = manifest, includeDummyDex = false)
        val missingDexOutcome = DrebinApkExtractor.extract(missingDex, schema)
        assertTrue(
            "Valid manifest without DEX must be UNSCANNABLE/DEX_MISSING",
            missingDexOutcome is DrebinApkExtractor.Outcome.Unscannable &&
                missingDexOutcome.reason == DrebinApkExtractor.Reason.DEX_MISSING
        )

        val missingManifest = File(root, "fixture-missing-manifest.apk")
        writeZipFixture(missingManifest, manifest = null, includeDummyDex = true)
        val missingManifestOutcome = DrebinApkExtractor.extract(missingManifest, schema)
        assertTrue(
            "APK without AndroidManifest.xml must be UNSCANNABLE/MANIFEST_INVALID",
            missingManifestOutcome is DrebinApkExtractor.Outcome.Unscannable &&
                missingManifestOutcome.reason == DrebinApkExtractor.Reason.MANIFEST_INVALID
        )

        val malformedManifest = File(root, "fixture-malformed-manifest.apk")
        writeZipFixture(malformedManifest, manifest = byteArrayOf(1, 2, 3, 4), includeDummyDex = true)
        val malformedManifestOutcome = DrebinApkExtractor.extract(malformedManifest, schema)
        assertTrue(
            "Malformed binary manifest must be UNSCANNABLE/MANIFEST_INVALID",
            malformedManifestOutcome is DrebinApkExtractor.Outcome.Unscannable &&
                malformedManifestOutcome.reason == DrebinApkExtractor.Reason.MANIFEST_INVALID
        )

        val malformedZip = File(root, "fixture-malformed-zip.apk")
        malformedZip.writeBytes(byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7))
        val malformedZipOutcome = DrebinApkExtractor.extract(malformedZip, schema)
        assertTrue(
            "Malformed ZIP/APK must be UNSCANNABLE",
            malformedZipOutcome is DrebinApkExtractor.Outcome.Unscannable
        )

        return JSONObject()
            .put("binary_manifest_permission_fixture_passed", true)
            .put("binary_manifest_action_fixture_passed", true)
            .put("valid_manifest_missing_dex_reason", "DEX_MISSING")
            .put("missing_manifest_reason", "MANIFEST_INVALID")
            .put("malformed_manifest_reason", "MANIFEST_INVALID")
            .put("malformed_zip_reason", (malformedZipOutcome as DrebinApkExtractor.Outcome.Unscannable).reason.name)
            .put("fixture_scope", "synthetic ZIP and binary AndroidManifest parser edge cases; DEX traversal is separately probed on the installed app APK")
    }

    private fun writeZipFixture(file: File, manifest: ByteArray?, includeDummyDex: Boolean) {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            if (manifest != null) {
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(manifest)
                zip.closeEntry()
            }
            if (includeDummyDex) {
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(ByteArray(64) { if (it == 0) 0x64 else 0 })
                zip.closeEntry()
            }
        }
    }

    private fun createBinaryManifestFixture(): ByteArray {
        val strings = listOf(
            "uses-permission", "action", "name",
            "android.permission.INTERNET", "android.intent.action.BOOT_COMPLETED",
        )
        val stringData = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        for (value in strings) {
            val encoded = value.toByteArray(Charsets.UTF_8)
            require(encoded.size < 128 && value.length < 128)
            offsets += stringData.size()
            stringData.write(value.length)
            stringData.write(encoded.size)
            stringData.write(encoded)
            stringData.write(0)
        }

        val headerSize = 28
        val stringsStart = headerSize + offsets.size * 4
        val poolSize = stringsStart + stringData.size()
        val pool = ByteBuffer.allocate(poolSize).order(ByteOrder.LITTLE_ENDIAN)
        pool.putShort(0x0001.toShort())
        pool.putShort(headerSize.toShort())
        pool.putInt(poolSize)
        pool.putInt(strings.size)
        pool.putInt(0)
        pool.putInt(0x100)
        pool.putInt(stringsStart)
        pool.putInt(0)
        offsets.forEach { pool.putInt(it) }
        pool.put(stringData.toByteArray())

        fun startElement(tagIndex: Int, valueIndex: Int): ByteArray {
            val nodeSize = 56
            val node = ByteBuffer.allocate(nodeSize).order(ByteOrder.LITTLE_ENDIAN)
            node.putShort(0x0102.toShort())
            node.putShort(36.toShort())
            node.putInt(nodeSize)
            node.putInt(1)
            node.putInt(-1)
            node.putInt(-1)
            node.putInt(tagIndex)
            node.putShort(20.toShort())
            node.putShort(20.toShort())
            node.putShort(1.toShort())
            node.putShort(0)
            node.putShort(0)
            node.putShort(0)
            node.putInt(-1)
            node.putInt(2) // attribute name "name"
            node.putInt(valueIndex)
            node.putShort(8.toShort())
            node.put(0)
            node.put(0x03)
            node.putInt(valueIndex)
            return node.array()
        }

        val permission = startElement(0, 3)
        val action = startElement(1, 4)
        val totalSize = 8 + poolSize + permission.size + action.size
        val rootHeader = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(0x0003.toShort())
            .putShort(8.toShort())
            .putInt(totalSize)
            .array()
        return ByteArray(totalSize).also { output ->
            var offset = 0
            listOf(rootHeader, pool.array(), permission, action).forEach { chunk ->
                chunk.copyInto(output, offset)
                offset += chunk.size
            }
        }
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
        const val COLD_INTERPRETER_REPETITIONS = 30
        const val REUSED_INTERPRETER_ITERATIONS = 1_000
        const val PRODUCTION_WARMUP_CALLS = 5
        const val PRODUCTION_PATH_ITERATIONS = 300
        val MEMORY_MILESTONES = setOf(1, 10, 50, 300)
        val CLASS_FEATURE_NAMES = setOf(
            "ServiceConnection", "ClassLoader", "DexClassLoader", "SecretKey", "KeySpec",
            "Binder", "IBinder", "URLClassLoader", "PathClassLoader", "PackageInstaller",
            "HttpUriRequest", "MessengerService", "IRemoteService", "ProcessBuilder",
            "android.os.Binder", "android.os.IBinder", "android.content.pm.Signature",
            "android.telephony.SmsManager", "android.telephony.gsm.SmsManager",
            "android.content.pm.PackageInfo", "Ljava.net.URLDecoder",
            "Ljavax.crypto.spec.SecretKeySpec", "Ljavax.crypto.Cipher",
        )
        val CALLBACK_NAMES = setOf("onBind", "onServiceConnected")
        val COMMAND_NAMES = setOf("mount", "remount", "chmod", "chown")
        const val EXPECTED_MODEL_BYTES = 18_584
        const val EXPECTED_MODEL_SHA256 =
            "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"
        const val EXPECTED_SCHEMA_SHA256 =
            "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
    }
}
