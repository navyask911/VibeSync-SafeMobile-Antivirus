package com.vibesync.antivirus.core.engine

import android.content.Context
import android.content.pm.PackageInfo
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.tensorflow.lite.DataType
import org.tensorflow.lite.Interpreter

/**
 * Fully offline, typed 215-feature extraction. The downloadable research model is never
 * promoted to a production detector; an independently validated, APK-signed metadata
 * manifest is required before ANY ML result can contribute to risk scoring.
 * APKs are not read into memory in their entirety: feature extraction streams
 * bounded ZIP/DEX entries, and the production model gate skips inactive models.
 */
class MachineLearningScanner(context: Context) {
    data class Prediction(val probability: Float)
    private val app = context.applicationContext

    suspend fun isAvailable(): Boolean = withContext(Dispatchers.IO) {
        val schema = DrebinFeatureContract.loadSchema(app.assets)
        schema != null && runCatching { validatedModelBytes(schema) != null }.getOrDefault(false)
    }

    /** Used by validation tests and future approved scanners; returns explicit Unscannable
     * rather than interpreting incomplete/malformed APK features as zeroes.
     */
    internal suspend fun extractFeatureVector(apk: File): DrebinApkExtractor.Outcome {
        val schema = DrebinFeatureContract.loadSchema(app.assets)
            ?: return DrebinApkExtractor.Outcome.Unscannable(
                DrebinApkExtractor.Reason.MANIFEST_INVALID)
        return DrebinApkExtractor.extract(apk, schema)
    }

    // Experimental research scoring for the provenance-gated cloud benchmark only.
    // Production PackageScanner continues using scan(), which requires validated production metadata.
    internal suspend fun scanResearchCandidate(apk: File): Prediction? = score(apk, allowResearch = true)

    suspend fun isResearchCandidateAvailable(): Boolean = withContext(Dispatchers.IO) {
        val schema = DrebinFeatureContract.loadSchema(app.assets)
        schema != null && runCatching { validatedModelBytes(schema, allowResearch = true) != null }.getOrDefault(false)
    }

    suspend fun scan(apk: File, @Suppress("UNUSED_PARAMETER") info: PackageInfo?): Prediction? =
        score(apk, allowResearch = false)

    private suspend fun score(apk: File, allowResearch: Boolean): Prediction? =
        withTimeoutOrNull(TOTAL_TIMEOUT_MS) {
            withContext(Dispatchers.IO) {
                try {
                    val schema = DrebinFeatureContract.loadSchema(app.assets)
                        ?: return@withContext null
                    val model = validatedModelBytes(schema, allowResearch) ?: return@withContext null
                    val extracted = DrebinApkExtractor.extract(apk, schema)
                    val vector = (extracted as? DrebinApkExtractor.Outcome.Features)?.vector
                        ?: return@withContext null // Explicit UNSCANNABLE never becomes benign.
                    val inputBuffer = ByteBuffer.allocateDirect(model.size)
                        .order(ByteOrder.nativeOrder())
                    inputBuffer.put(model)
                    inputBuffer.rewind()
                    Interpreter(inputBuffer, Interpreter.Options().setNumThreads(1)).use { interpreter ->
                        interpreter.allocateTensors()
                        if (interpreter.inputTensorCount != 1 || interpreter.outputTensorCount != 1)
                            return@withContext null
                        val input = interpreter.getInputTensor(0)
                        val output = interpreter.getOutputTensor(0)
                        if (!input.shape().contentEquals(intArrayOf(1, schema.size)) ||
                            !output.shape().contentEquals(intArrayOf(1, 1)) ||
                            input.dataType() != DataType.FLOAT32 || output.dataType() != DataType.FLOAT32)
                            return@withContext null
                        val result = Array(1) { FloatArray(1) }
                        interpreter.run(arrayOf(vector), result)
                        val score = result[0][0]
                        if (score.isFinite() && score in 0f..1f) Prediction(score) else null
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    null
                } catch (_: LinkageError) {
                    null
                }
            }
        }

    private fun validatedModelBytes(schema: List<String>, allowResearch: Boolean = false): ByteArray? {
        val metadata = app.assets.open("malware_model.json").bufferedReader().use {
            JSONObject(it.readText())
        }
        val approvedProduction = metadata.optBoolean("trained") &&
            metadata.optBoolean("validated") && metadata.optBoolean("production_ready") &&
            metadata.optString("status") == "validated_production"
        val approvedResearch = allowResearch && metadata.optBoolean("trained") &&
            !metadata.optBoolean("validated") && !metadata.optBoolean("production_ready") &&
            !metadata.optBoolean("dummy_untrained", true) &&
            metadata.optString("status") == "research_candidate"
        if ((!approvedProduction && !approvedResearch) ||
            metadata.optInt("schema_version") != 1 ||
            metadata.optInt("feature_count") != schema.size) return null
        val named = metadata.optJSONArray("features") ?: return null
        if (named.length() != schema.size ||
            schema.indices.any { index -> named.optString(index) != schema[index] }) return null
        val expected = metadata.optString("model_sha256")
        if (!Regex("[0-9a-f]{64}").matches(expected)) return null
        val bytes = app.assets.open("malware_model.tflite").use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                if (output.size() + n >= MAX_BYTES) return null
                output.write(buffer, 0, n)
            }
            output.toByteArray()
        }
        if (bytes.size < 64 || String(bytes, 4, 4, Charsets.US_ASCII) != "TFL3") return null
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        return bytes.takeIf { digest == expected }
    }

    companion object {
        private const val MAX_BYTES = 20 * 1024 * 1024
        private const val TOTAL_TIMEOUT_MS = 8000L
        const val THRESHOLD = 0.85f // Legacy advisory threshold; never used while disabled.
    }
}
