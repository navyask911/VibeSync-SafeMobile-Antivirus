package com.vibesync.antivirus.core.engine
import android.content.Context
import android.util.Log
import org.tensorflow.lite.Interpreter
import java.nio.ByteBuffer
import java.nio.ByteOrder
/** Optional TFLite runner. No synthetic model is bundled; missing model returns null. */
class PermissionModelScorer(context: Context) {
 private val app = context.applicationContext
 private val interpreter: Interpreter? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
  runCatching {
   val bytes = app.assets.open(MODEL_ASSET).use { it.readBytes() }
   require(bytes.isNotEmpty())
   Interpreter(ByteBuffer.allocateDirect(bytes.size).order(ByteOrder.nativeOrder()).apply { put(bytes); rewind() })
  }.onFailure { Log.i(TAG, "Optional model missing or invalid; using heuristic score.") }.getOrNull()
 }
 fun probability(features: FloatArray): Float? {
  if (features.size != FEATURE_COUNT) return null
  val runtime = interpreter ?: return null
  return runCatching {
   val output = Array(1) { FloatArray(1) }
   synchronized(runtime) { runtime.run(arrayOf(features.copyOf()), output) }
   output[0][0].takeIf { it.isFinite() && it in 0f..1f }
  }.onFailure { Log.w(TAG, "Permission model inference failed; heuristic fallback selected.", it) }.getOrNull()
 }
 companion object { const val MODEL_ASSET = "permission_risk.tflite"; const val FEATURE_COUNT = 30; private const val TAG = "SafeMobileModel" }
}
