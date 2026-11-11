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
import org.tensorflow.lite.DataType
import org.tensorflow.lite.Interpreter

/**
 * Fully offline, typed 215-feature extraction. The approved research model is
 * retrieved from the separate ML repository by the Gradle build bridge and pinned
 * by model/schema SHA-256. Release metadata is source-pinned; the model remains
 * research-only and production classification stays disabled until independent
 * contemporary APK validation and approval.
 *
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

    /**
     * Metadata mirrored from the immutable v1.0.1-model release contract.
     * The research candidate remains deliberately unvalidated and production-disabled.
     * Any production activation requires a reviewed source change after independent validation.
     */
    private fun validatedModelBytes(schema: List<String>, allowResearch: Boolean = false): ByteArray? {
        val approvedProduction = MODEL_VALIDATED && MODEL_PRODUCTION_READY &&
            MODEL_STATUS == "validated_production"
        val approvedResearch = allowResearch && MODEL_TRAINED &&
            !MODEL_VALIDATED && !MODEL_PRODUCTION_READY &&
            !MODEL_DUMMY_UNTRAINED && MODEL_STATUS == "research_candidate"
        if ((!approvedProduction && !approvedResearch) || schema.size != FEATURE_COUNT) return null

        val schemaBytes = app.assets.open(SCHEMA_ASSET_NAME).use { input ->
            input.readBytes().takeIf { it.size in 100..MAX_SCHEMA_BYTES } ?: return null
        }
        val schemaDigest = MessageDigest.getInstance("SHA-256").digest(schemaBytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        if (schemaDigest != APPROVED_SCHEMA_SHA256) return null

        val bytes = app.assets.open(MODEL_ASSET_NAME).use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size().toLong() + count > MAX_BYTES) return null
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        if (bytes.size != APPROVED_MODEL_SIZE ||
            String(bytes, 4, 4, Charsets.US_ASCII) != "TFL3") return null
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return bytes.takeIf { digest == APPROVED_MODEL_SHA256 }
    }

    companion object {
        private const val MAX_BYTES = 20 * 1024 * 1024
        private const val MAX_SCHEMA_BYTES = 32 * 1024
        private const val TOTAL_TIMEOUT_MS = 8000L
        private const val MODEL_ASSET_NAME = "model.tflite"
        private const val SCHEMA_ASSET_NAME = "feature_schema.json"
        private const val APPROVED_MODEL_SIZE = 18_584
        private const val FEATURE_COUNT = 215
        private const val APPROVED_MODEL_SHA256 =
            "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"
        private const val APPROVED_SCHEMA_SHA256 =
            "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
        private const val MODEL_STATUS = "research_candidate"
        private const val MODEL_TRAINED = true
        private const val MODEL_VALIDATED = false
        private const val MODEL_PRODUCTION_READY = false
        private const val MODEL_DUMMY_UNTRAINED = false
        const val THRESHOLD = 0.85f // Legacy advisory threshold; never used while production-disabled.
    }
}
