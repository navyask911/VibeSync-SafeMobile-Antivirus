package com.vibesync.antivirus.engine.ml

import android.content.Context
import java.io.ByteArrayOutputStream
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
 * Local-only TensorFlow Lite inference for the build-time downloaded Drebin-215 research bundle.
 *
 * The asset is pinned to the publisher's v1.0.1-model SHA-256. Input/output tensor
 * dimensions and data types are checked before execution. This layer returns only
 * a probability; it deliberately does not classify, score, or alter scan verdicts.
 */
class TfliteInferenceEngine(context: Context) {
    private val appContext = context.applicationContext

    suspend fun runInference(features: FloatArray): Float? =
        withTimeoutOrNull(INFERENCE_TIMEOUT_MS) {
            withContext(Dispatchers.IO) {
                if (features.size != INPUT_FEATURE_COUNT ||
                    features.any { it != 0.0f && it != 1.0f }) {
                    return@withContext null
                }

                try {
                    val modelBytes = readModelAsset() ?: return@withContext null
                    val modelBuffer = ByteBuffer.allocateDirect(modelBytes.size)
                        .order(ByteOrder.nativeOrder())
                        .apply {
                            put(modelBytes)
                            rewind()
                        }

                    Interpreter(modelBuffer, Interpreter.Options().setNumThreads(1)).use { interpreter ->
                        interpreter.allocateTensors()
                        if (interpreter.inputTensorCount != 1 ||
                            interpreter.outputTensorCount != 1) {
                            return@withContext null
                        }

                        val input = interpreter.getInputTensor(0)
                        val output = interpreter.getOutputTensor(0)
                        if (!input.shape().contentEquals(intArrayOf(1, INPUT_FEATURE_COUNT)) ||
                            !output.shape().contentEquals(intArrayOf(1, 1)) ||
                            input.dataType() != DataType.FLOAT32 ||
                            output.dataType() != DataType.FLOAT32) {
                            return@withContext null
                        }

                        val result = Array(1) { FloatArray(1) }
                        interpreter.run(arrayOf(features), result)
                        result[0][0].takeIf { it.isFinite() && it in 0.0f..1.0f }
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

    private fun readModelAsset(): ByteArray? {
        val bytes = appContext.assets.open(MODEL_ASSET_NAME).use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size().toLong() + count > MAX_MODEL_BYTES) return null
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        if (bytes.size != APPROVED_MODEL_SIZE ||
            String(bytes, 4, 4, Charsets.US_ASCII) != "TFL3") {
            return null
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return bytes.takeIf { digest == APPROVED_MODEL_SHA256 }
    }

    companion object {
        const val INPUT_FEATURE_COUNT = 215
        const val MALWARE_THRESHOLD = 0.5f

        private const val MODEL_ASSET_NAME = "model.tflite"
        private const val APPROVED_MODEL_SIZE = 18_584
        private const val APPROVED_MODEL_SHA256 =
            "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"
        private const val MAX_MODEL_BYTES = 20L * 1024 * 1024
        private const val INFERENCE_TIMEOUT_MS = 5_000L
    }
}
