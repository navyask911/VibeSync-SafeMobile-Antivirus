package com.vibesync.antivirus.validation

import android.app.ActivityManager
import android.content.Context
import androidx.room.Room
import android.os.Build
import android.os.Debug
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.core.engine.DrebinApkExtractor
import com.vibesync.antivirus.core.engine.PackageScanner
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.data.local.ThreatDatabase
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
import java.util.UUID

/**
 * Private device-side parity and timing data collector.
 * Push APKs into getExternalFilesDir("drebin-validation")/apks before running.
 * Supply -e appCommit=<exact 40-character source SHA>.
 * Output contains sample vectors and stays in app-scoped external storage.
 */
@RunWith(AndroidJUnit4::class)
class DrebinDeviceValidationHarnessTest {
    @Test
    public fun exportPairedVectorsAndMeasureInference(): Unit {
        runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val args = InstrumentationRegistry.getArguments()
        val appCommit = args.getString("appCommit").orEmpty()
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
        val installedComponentFiles = (
            listOf("base" to selfApk) +
                context.applicationInfo.splitSourceDirs.orEmpty().mapIndexed { index, path ->
                    "split_$index" to File(path)
                }
            ).distinctBy { it.second.absolutePath }

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

        val installedPackageComponents = JSONArray()
        val installedComponentVectors = mutableListOf<Pair<String, FloatArray>>()
        for ((componentName, componentApk) in installedComponentFiles) {
            val componentSha = sha256(componentApk)
            when (val result = DrebinApkExtractor.extract(componentApk, schema)) {
                is DrebinApkExtractor.Outcome.Features -> {
                    installedComponentVectors += componentName to result.vector
                    installedPackageComponents.put(JSONObject()
                        .put("component", componentName)
                        .put("apk_sha256", componentSha)
                        .put("status", "FEATURES")
                        .put("active_feature_count", result.vector.count { it == 1.0f })
                        .put("feature_indices", JSONArray().also { indices ->
                            result.vector.forEachIndexed { index, value -> if (value == 1.0f) indices.put(index) }
                        })
                        .put("vector", JSONArray().also { vector ->
                            result.vector.forEach { vector.put(it.toInt()) }
                        }))
                }
                is DrebinApkExtractor.Outcome.Unscannable -> {
                    installedPackageComponents.put(JSONObject()
                        .put("component", componentName)
                        .put("apk_sha256", componentSha)
                        .put("status", "UNSCANNABLE")
                        .put("reason", result.reason.name))
                }
            }
        }
        val baseVector = installedComponentVectors.firstOrNull { it.first == "base" }?.second
        val aggregateVector = if (installedComponentVectors.isNotEmpty()) {
            FloatArray(215) { index ->
                if (installedComponentVectors.any { it.second[index] == 1.0f }) 1.0f else 0.0f
            }
        } else null
        val splitOnlyFeatureIndices = if (baseVector != null && aggregateVector != null) {
            (0 until 215).filter { aggregateVector[it] == 1.0f && baseVector[it] == 0.0f }
        } else emptyList()

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
        val packageScannerBenchmark = if (
            args.getString("runPackageScanner").equals("true", ignoreCase = true)
        ) {
            runPackageScannerBenchmark(context, args.getString("packageScanLimit")?.toIntOrNull() ?: 10)
        } else {
            JSONObject()
                .put("executed", false)
                .put("reason", "Opt in with -e runPackageScanner true; this scans installed third-party apps")
        }

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
            .put("installed_package_components", installedPackageComponents)
            .put("installed_package_split_only_feature_indices", JSONArray(splitOnlyFeatureIndices))
            .put("installed_package_component_aggregate_feature_count", aggregateVector?.count { it == 1.0f } ?: JSONObject.NULL)
            .put("apk_results", apkResults)
            .put("package_scanner_benchmark", packageScannerBenchmark)
            .put("scope", "APK feature extraction plus ML inference; not full PackageScanner/YARA/hash scan")
            .put("private_data_warning", "Contains per-APK vectors; keep local and do not commit or publish samples")

        val outputDirectory = File(root, "results")
        check(outputDirectory.mkdirs() || outputDirectory.isDirectory)
        val outputFile = File(outputDirectory, "drebin-device-validation.json")
        outputFile.writeText(output.toString(2), Charsets.UTF_8)

        // A separate, sanitized summary can be collected by CI without exporting
        // any per-APK feature vector or installed package name.
        val componentSummaries = JSONArray()
        for (index in 0 until installedPackageComponents.length()) {
            val component = installedPackageComponents.getJSONObject(index)
            componentSummaries.put(JSONObject()
                .put("component", component.optString("component"))
                .put("apk_sha256", component.optString("apk_sha256"))
                .put("status", component.optString("status"))
                .put("active_feature_count", component.opt("active_feature_count") ?: JSONObject.NULL))
        }
        val packageScannerSummary = JSONObject()
            .put("executed", packageScannerBenchmark.optBoolean("executed", false))
        if (packageScannerBenchmark.optBoolean("executed", false)) {
            packageScannerSummary
                .put("scan_scope", packageScannerBenchmark.optString("scan_scope"))
                .put("inventory_candidates", packageScannerBenchmark.optInt("inventory_candidates"))
                .put("cold_scan_latency", packageScannerBenchmark.optJSONObject("cold_scan_latency"))
                .put("warm_repeat_scan_latency", packageScannerBenchmark.optJSONObject("warm_repeat_scan_latency"))
                .put("memory_before", packageScannerBenchmark.optJSONObject("memory_before"))
                .put("memory_after_all_scans", packageScannerBenchmark.optJSONObject("memory_after_all_scans"))
        }
        val safeSummary = JSONObject()
            .put("report_version", 1)
            .put("schema_sha256", schemaSha)
            .put("model_sha256", modelSha)
            .put("model_bytes", modelBytes.size)
            .put("android_app", output.getJSONObject("android_app"))
            .put("benchmark", output.getJSONObject("benchmark"))
            .put("apk_corpus", output.getJSONObject("apk_corpus"))
            .put("contract_fixtures", contractFixtureSummary)
            .put("apk_parser_fixtures", apkParserFixtureSummary)
            .put("installed_app_base_apk_probe", selfApkProbe)
            .put("installed_package_component_summaries", componentSummaries)
            .put("installed_package_split_only_feature_indices", JSONArray(splitOnlyFeatureIndices))
            .put("installed_package_component_aggregate_feature_count",
                aggregateVector?.count { it == 1.0f } ?: JSONObject.NULL)
            .put("package_scanner_benchmark", packageScannerSummary)
            .put("private_vectors_or_package_names_included", false)
        context.openFileOutput("drebin-validation-summary.json", Context.MODE_PRIVATE).bufferedWriter().use {
            it.write(safeSummary.toString(2))
        }

        assertTrue("Production inference must return valid scores", nullProductionScores == 0)
        assertEquals(apkFiles.size, apkResults.length())
        android.util.Log.i(TAG, "Validation artifact written to ${outputFile.absolutePath}")
        }
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
        writeZipFixture(malformedManifest, manifest = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), includeDummyDex = true)
        val malformedManifestOutcome = DrebinApkExtractor.extract(malformedManifest, schema)
        assertTrue(
            "Malformed binary manifest must be UNSCANNABLE/MANIFEST_INVALID",
            malformedManifestOutcome is DrebinApkExtractor.Outcome.Unscannable &&
                malformedManifestOutcome.reason == DrebinApkExtractor.Reason.MANIFEST_INVALID
        )

        val malformedDex = File(root, "fixture-malformed-dex.apk")
        writeZipFixture(malformedDex, manifest = manifest, includeDummyDex = true)
        val malformedDexOutcome = DrebinApkExtractor.extract(malformedDex, schema)
        assertTrue(
            "Malformed DEX must be UNSCANNABLE/DEX_INVALID",
            malformedDexOutcome is DrebinApkExtractor.Outcome.Unscannable &&
                malformedDexOutcome.reason == DrebinApkExtractor.Reason.DEX_INVALID
        )

        val entryLimitApk = File(root, "fixture-entry-limit.apk")
        writeEntryLimitFixture(entryLimitApk)
        val entryLimitOutcome = DrebinApkExtractor.extract(entryLimitApk, schema)
        assertTrue(
            "APK exceeding ZIP entry budget must be UNSCANNABLE/LIMIT_EXCEEDED",
            entryLimitOutcome is DrebinApkExtractor.Outcome.Unscannable &&
                entryLimitOutcome.reason == DrebinApkExtractor.Reason.LIMIT_EXCEEDED
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
            .put("malformed_dex_reason", (malformedDexOutcome as DrebinApkExtractor.Outcome.Unscannable).reason.name)
            .put("zip_entry_limit_reason", (entryLimitOutcome as DrebinApkExtractor.Outcome.Unscannable).reason.name)
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

    private fun writeEntryLimitFixture(file: File) {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            repeat(1_801) { index ->
                zip.putNextEntry(ZipEntry("entry-$index"))
                zip.write(0)
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
        val unpaddedPoolSize = stringsStart + stringData.size()
        val padding = (4 - unpaddedPoolSize % 4) % 4
        repeat(padding) { stringData.write(0) }
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
            node.putShort(0.toShort())
            node.putShort(0.toShort())
            node.putShort(0)
            node.putInt(-1)
            node.putInt(2) // attribute name "name"
            node.putInt(valueIndex)
            node.putShort(8.toShort())
            node.put(0.toByte())
            node.put(0x03.toByte())
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

    private suspend fun runPackageScannerBenchmark(context: Context, requestedLimit: Int): JSONObject {
        val limit = requestedLimit.coerceIn(1, 20)
        val database = Room.inMemoryDatabaseBuilder(
            context, ThreatDatabase::class.java
        ).build()
        try {
            val scanner = PackageScanner(
                context = context,
                dao = database.threatDao(),
                hashStore = EncryptedHashStore(context),
            )
            val inventory = scanner.installedAppInventory().take(limit)
            val packageRuns = JSONArray()
            val coldDurations = mutableListOf<Long>()
            val warmDurations = mutableListOf<Long>()
            val memoryBefore = memorySnapshot(context)

            for (item in inventory) {
                val coldStart = SystemClock.elapsedRealtimeNanos()
                val coldResult = runCatching {
                    scanner.scanInstalledPackage(item.packageName, UUID.randomUUID().toString())
                }
                val coldElapsed = SystemClock.elapsedRealtimeNanos() - coldStart
                coldDurations += coldElapsed
                val memoryAfterCold = memorySnapshot(context)

                val warmStart = SystemClock.elapsedRealtimeNanos()
                val warmResult = runCatching {
                    scanner.scanInstalledPackage(item.packageName, UUID.randomUUID().toString())
                }
                val warmElapsed = SystemClock.elapsedRealtimeNanos() - warmStart
                warmDurations += warmElapsed
                val memoryAfterWarm = memorySnapshot(context)

                packageRuns.put(JSONObject()
                    .put("package_name", item.packageName)
                    .put("cold_scan_ms", coldElapsed / 1_000_000.0)
                    .put("cold_scan_verdict", coldResult.getOrNull()?.verdict?.name ?: "NULL_OR_ERROR")
                    .put("cold_scan_succeeded", coldResult.isSuccess)
                    .put("warm_repeat_scan_ms", warmElapsed / 1_000_000.0)
                    .put("warm_repeat_scan_verdict", warmResult.getOrNull()?.verdict?.name ?: "NULL_OR_ERROR")
                    .put("warm_repeat_scan_succeeded", warmResult.isSuccess)
                    .put("cold_error_type", coldResult.exceptionOrNull()?.javaClass?.simpleName)
                    .put("warm_error_type", warmResult.exceptionOrNull()?.javaClass?.simpleName)
                    .put("memory_after_cold", memoryAfterCold)
                    .put("memory_after_warm", memoryAfterWarm))
            }

            return JSONObject()
                .put("executed", true)
                .put("scan_scope", "PackageScanner.scanInstalledPackage on installed third-party inventory")
                .put("database", "Room in-memory database; user application database is not opened")
                .put("requested_package_limit", limit)
                .put("inventory_candidates", inventory.size)
                .put("cold_scan_latency", summarize(coldDurations))
                .put("warm_repeat_scan_latency", summarize(warmDurations))
                .put("memory_before", memoryBefore)
                .put("memory_after_all_scans", memorySnapshot(context))
                .put("package_runs", packageRuns)
                .put("privacy_note", "Contains installed package names; keep the output on the private test device")
        } finally {
            database.close()
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
