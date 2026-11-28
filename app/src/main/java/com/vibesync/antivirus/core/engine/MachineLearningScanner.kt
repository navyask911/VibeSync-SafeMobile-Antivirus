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
 * Fully offline, typed 215-feature extraction. The v1.0.1-model bundle is retrieved
 * from the separate ML repository by the Gradle build bridge and pinned by model/schema
 * SHA-256. It is a research candidate, not an independently validated production classifier.
 * Controlled research inference may return an advisory score; the production scanner gate
 * remains closed until independent validation and device-readiness evidence is approved.
 *
 * APKs are not read into memory in their entirety: feature extraction streams
 * bounded ZIP/DEX entries, and unavailable or invalid model data fails closed.
 */
class MachineLearningScanner(context: Context) {
    data class Prediction(val probability: Float)
    private val app = context.applicationContext

    /** True only after independent validation and explicit production approval. */
    suspend fun isAvailable(): Boolean = withContext(Dispatchers.IO) {
        val schema = DrebinFeatureContract.loadSchema(app.assets)
        schema != null && runCatching { validatedModelBytes(schema) != null }.getOrDefault(false)
    }

    /** Used by validation tests and future approved scanners; returns explicit Unscannable
     * rather than interpreting incomplete/malformed APK features as zeroes.
     */
    internal suspend fun extractFeatureVector(apk: File): DrebinApkExtractor.Outcome =
        extractFeatureVector(listOf(apk))

    internal suspend fun extractFeatureVector(apks: List<File>): DrebinApkExtractor.Outcome {
        val schema = DrebinFeatureContract.loadSchema(app.assets)
            ?: return DrebinApkExtractor.Outcome.Unscannable(
                DrebinApkExtractor.Reason.SCHEMA_INVALID)
        return DrebinApkExtractor.extract(apks, schema)
    }

    // Explicit research-only score path. This never upgrades the normal production gate.
    internal suspend fun scanResearchCandidate(apk: File): Prediction? =
        score(listOf(apk), allowResearch = true)

    internal suspend fun scanResearchCandidate(apks: List<File>): Prediction? =
        score(apks, allowResearch = true)

    suspend fun isResearchCandidateAvailable(): Boolean = withContext(Dispatchers.IO) {
        val schema = DrebinFeatureContract.loadSchema(app.assets)
        val researchMetadataEnabled = MODEL_TRAINED && !MODEL_VALIDATED &&
            !MODEL_PRODUCTION_READY && !MODEL_DUMMY_UNTRAINED &&
            MODEL_STATUS == "research_candidate"
        schema != null && researchMetadataEnabled &&
            runCatching { validatedModelBytes(schema, allowResearch = true) != null }.getOrDefault(false)
    }

    suspend fun scan(apk: File, @Suppress("UNUSED_PARAMETER") info: PackageInfo?): Prediction? =
        score(listOf(apk), allowResearch = false)

    private suspend fun score(apks: List<File>, allowResearch: Boolean): Prediction? =
        withTimeoutOrNull(TOTAL_TIMEOUT_MS) {
            withContext(Dispatchers.IO) {
                try {
                    val schema = DrebinFeatureContract.loadSchema(app.assets)
                        ?: return@withContext null
                    val model = validatedModelBytes(schema, allowResearch) ?: return@withContext null
                    val extracted = DrebinApkExtractor.extract(apks, schema)
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
     * Metadata mirrored from the immutable v1.0.1-model research bundle.
     * SHA/schema/tensor compatibility proves artifact integrity, not classifier validation.
     * The normal production path remains closed until independent validation and approval.
     */
    private fun validatedModelBytes(schema: List<String>, allowResearch: Boolean = false): ByteArray? {
        val approvedProduction = !allowResearch && MODEL_VALIDATED && MODEL_PRODUCTION_READY &&
            MODEL_STATUS == "active"
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
        const val THRESHOLD = 0.5f // Published bundle metadata; the app's advisory fusion thresholds are separate.
    }
}
