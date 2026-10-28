package com.vibesync.antivirus.core.engine

import android.content.Context
import android.content.pm.PackageInfo
import android.os.SystemClock
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipFile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONObject
import org.tensorflow.lite.Interpreter

/**
 * Opt-in, entirely offline static feature inference.
 * A demo model and any unreviewed trained model are NEVER treated as malware detectors.
 * The separately reviewed asset manifest must declare trained and validated AND bind the
 * exact model digest; otherwise this layer stays unavailable and other engines continue.
 */
class MachineLearningScanner(private val context: Context) {
    data class Prediction(val probability: Float)
    private val appContext = context.applicationContext

    suspend fun isAvailable(): Boolean = withContext(Dispatchers.IO) {
        runCatching { validatedModelBytes() != null }.getOrDefault(false)
    }

    suspend fun scan(apk: File, info: PackageInfo?): Prediction? =
        withTimeoutOrNull(TOTAL_TIMEOUT_MS) {
            withContext(Dispatchers.IO) {
                try {
                    val model = validatedModelBytes() ?: return@withContext null
                    val vector = extractFeatures(apk, info) ?: return@withContext null
                    val buffer = ByteBuffer.allocateDirect(model.size).order(ByteOrder.nativeOrder())
                    buffer.put(model)
                    buffer.rewind()
                    val options = Interpreter.Options().setNumThreads(1)
                    Interpreter(buffer, options).use { interpreter ->
                        interpreter.allocateTensors()
                        val input = interpreter.getInputTensor(0)
                        val output = interpreter.getOutputTensor(0)
                        require(input.shape().contentEquals(intArrayOf(1, FEATURE_COUNT)))
                        require(output.shape().contentEquals(intArrayOf(1, 1)))
                        require(input.dataType() == org.tensorflow.lite.DataType.FLOAT32)
                        require(output.dataType() == org.tensorflow.lite.DataType.FLOAT32)
                        val scores = Array(1) { FloatArray(1) }
                        interpreter.run(arrayOf(vector), scores)
                        val score = scores[0][0]
                        if (score.isFinite() && score in 0f..1f) Prediction(score) else null
                    }
                } catch (cancel: CancellationException) {
                    throw cancel
                } catch (_: Exception) {
                    // Corrupt, mismatched, expired or missing models do not affect YARA/hash scanning.
                    null
                } catch (_: LinkageError) {
                    // TFLite native runtime unavailable on a device.
                    null
                }
            }
        }

    private fun validatedModelBytes(): ByteArray? {
        val metadata = appContext.assets.open("malware_model.json").bufferedReader().use {
            JSONObject(it.readText())
        }
        if (!metadata.optBoolean("trained") || !metadata.optBoolean("validated") ||
            metadata.optInt("schema_version") != 1 ||
            metadata.optInt("feature_count") != FEATURE_COUNT ||
            metadata.optString("status") != "validated_production") return null
        val features = metadata.optJSONArray("features") ?: return null
        if (features.length() != FEATURES.size || FEATURES.indices.any { features.optString(it) != FEATURES[it] }) return null
        val hash = metadata.optString("model_sha256")
        if (!Regex("[0-9a-f]{64}").matches(hash)) return null
        val bytes = appContext.assets.open("malware_model.tflite").use { input ->
            val out = ByteArrayOutputStream(64 * 1024)
            val buf = ByteArray(8192)
            var total = 0
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total >= MAX_MODEL_BYTES) return null
                out.write(buf, 0, n)
            }
            out.toByteArray()
        }
        if (bytes.size < 64 || String(bytes, 4, 4, Charsets.US_ASCII) != "TFL3") return null
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }
        return bytes.takeIf { digest == hash }
    }

    private suspend fun extractFeatures(apk: File, info: PackageInfo?): FloatArray? {
        if (!apk.isFile || !apk.canRead() || apk.length() > MAX_APK_BYTES) return null
        val start = SystemClock.elapsedRealtime()
        val observed = mutableSetOf<String>()
        info?.requestedPermissions.orEmpty().forEach { observed += "perm." + it.substringAfterLast('.') }
        if (info?.services.orEmpty().any {
                it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE"
            }) observed += "perm.BIND_ACCESSIBILITY_SERVICE"
        val dexFragments = StringBuilder()
        val manifestFragments = StringBuilder()
        var inspected = 0
        var totalRead = 0
        ZipFile(apk).use { archive ->
            val entries = archive.entries()
            while (entries.hasMoreElements()) {
                currentCoroutineContext().ensureActive()
                if (SystemClock.elapsedRealtime() - start > EXTRACTION_BUDGET_MS) return null
                val entry = entries.nextElement()
                if (++inspected > MAX_ENTRIES) return null
                val manifest = entry.name == "AndroidManifest.xml"
                val dex = Regex("classes[0-9]*\\.dex").matches(entry.name)
                if (!manifest && !dex) continue
                if (entry.size < 0 || entry.size > MAX_ENTRY_BYTES) continue
                val remaining = MAX_READ_BYTES - totalRead
                if (remaining <= 0) break
                val maxRead = minOf(remaining, MAX_ENTRY_BYTES.toInt())
                val out = ByteArrayOutputStream(minOf(maxRead, 16384))
                archive.getInputStream(entry).use { input ->
                    val chunk = ByteArray(8192)
                    while (out.size() < maxRead) {
                        currentCoroutineContext().ensureActive()
                        if (SystemClock.elapsedRealtime() - start > EXTRACTION_BUDGET_MS) return null
                        val n = input.read(chunk, 0, minOf(chunk.size, maxRead - out.size()))
                        if (n < 0) break
                        out.write(chunk, 0, n)
                    }
                }
                totalRead += out.size()
                val bytes = out.toByteArray()
                if (dex) dexFragments.append(String(bytes, Charsets.ISO_8859_1).lowercase(Locale.ROOT))
                if (manifest) {
                    manifestFragments.append(String(bytes, Charsets.ISO_8859_1).lowercase(Locale.ROOT))
                    manifestFragments.append(String(bytes, Charsets.UTF_16LE).lowercase(Locale.ROOT))
                }
            }
        }
        // Manifest string-pool evidence is approximate; these bits do not prove the
        // action belongs to a registered intent filter. Exact training schema is fixed.
        val manifest = manifestFragments.toString()
        val dex = dexFragments.toString()
        for ((feature, token) in INTENT_TOKENS) {
            if (manifest.contains(token)) observed += feature
        }
        for ((feature, token) in API_TOKENS) {
            if (dex.contains(token)) observed += feature
        }
        return FloatArray(FEATURES.size) { i -> if (FEATURES[i] in observed) 1f else 0f }
    }

    companion object {
        private const val MAX_MODEL_BYTES = 50 * 1024 * 1024
        private const val MAX_APK_BYTES = 512L * 1024L * 1024L
        private const val MAX_ENTRIES = 1500
        private const val MAX_ENTRY_BYTES = 2L * 1024L * 1024L
        private const val MAX_READ_BYTES = 1024 * 1024
        private const val EXTRACTION_BUDGET_MS = 650L
        private const val TOTAL_TIMEOUT_MS = 1800L
        const val THRESHOLD = 0.85f
        const val FEATURE_COUNT = 32
        private val FEATURES = listOf(
            "perm.INTERNET", "perm.READ_SMS", "perm.RECEIVE_SMS", "perm.SEND_SMS",
            "perm.READ_CONTACTS", "perm.WRITE_CONTACTS", "perm.READ_CALL_LOG",
            "perm.WRITE_CALL_LOG", "perm.READ_PHONE_STATE", "perm.RECORD_AUDIO",
            "perm.CAMERA", "perm.ACCESS_FINE_LOCATION", "perm.ACCESS_COARSE_LOCATION",
            "perm.SYSTEM_ALERT_WINDOW", "perm.REQUEST_INSTALL_PACKAGES",
            "perm.QUERY_ALL_PACKAGES", "perm.READ_EXTERNAL_STORAGE",
            "perm.WRITE_EXTERNAL_STORAGE", "perm.RECEIVE_BOOT_COMPLETED",
            "perm.BIND_ACCESSIBILITY_SERVICE", "intent.BOOT_COMPLETED",
            "intent.SMS_RECEIVED", "intent.PACKAGE_ADDED",
            "intent.DEVICE_ADMIN_ENABLED", "intent.MAIN", "intent.VIEW",
            "api.SmsManager.sendTextMessage", "api.TelephonyManager.getDeviceId",
            "api.Runtime.exec", "api.DexClassLoader", "api.Class.forName",
            "api.AccessibilityService"
        )
        private val INTENT_TOKENS = listOf(
            "intent.BOOT_COMPLETED" to "android.intent.action.boot_completed",
            "intent.SMS_RECEIVED" to "android.provider.telephony.sms_received",
            "intent.PACKAGE_ADDED" to "android.intent.action.package_added",
            "intent.DEVICE_ADMIN_ENABLED" to "android.app.action.device_admin_enabled",
            "intent.MAIN" to "android.intent.action.main",
            "intent.VIEW" to "android.intent.action.view"
        )
        private val API_TOKENS = listOf(
            "api.SmsManager.sendTextMessage" to "smsmanager;->sendtextmessage",
            "api.TelephonyManager.getDeviceId" to "telephonymanager;->getdeviceid",
            "api.Runtime.exec" to "runtime;->exec",
            "api.DexClassLoader" to "ldalvik/system/dexclassloader;",
            "api.Class.forName" to "class;->forname",
            "api.AccessibilityService" to "landroid/accessibilityservice/accessibilityservice;"
        )
    }
}
