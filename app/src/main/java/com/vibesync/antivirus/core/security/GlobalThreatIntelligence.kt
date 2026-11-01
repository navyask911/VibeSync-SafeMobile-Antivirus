package com.vibesync.antivirus.core.security

import android.content.Context
import android.net.Uri
import android.util.Log
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.engine.DrebinApkExtractor
import com.vibesync.antivirus.core.engine.MachineLearningScanner
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/** Master contribution switch. Each sample still requires a separate Donate action. */
internal object GlobalThreatIntelligenceConsent {
    private const val KEY_ENABLED = "global_threat_intelligence_enabled"

    fun isEnabled(context: Context): Boolean =
        context.applicationContext
            .getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)

    fun setEnabled(context: Context, enabled: Boolean) {
        context.applicationContext
            .getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLED, enabled)
            .apply()
    }
}

/**
 * Strictly opt-in crowdsourced threat contribution.
 *
 * The JSON contains only the malware SHA-256 and its 215-bit Drebin feature vector.
 * APK bytes, names, paths, package names and device or user identifiers are never
 * serialized. No GitHub credentials are used or embedded in the Android client.
 */
internal class GlobalThreatIntelligenceDonor(context: Context) {
    private val app = context.applicationContext

    suspend fun donateInstalledPackage(packageName: String, detectedSha256: String): Boolean =
        withContext(Dispatchers.IO) {
            if (!GlobalThreatIntelligenceConsent.isEnabled(app)) return@withContext false
            val apk = runCatching {
                val info = app.packageManager.getApplicationInfo(packageName, 0)
                val path = info.sourceDir ?: info.publicSourceDir ?: return@runCatching null
                File(path)
            }.getOrNull() ?: return@withContext false
            donateApk(apk, detectedSha256)
        }

    suspend fun donateScanResult(result: ScanResult): Boolean = withContext(Dispatchers.IO) {
        if (!GlobalThreatIntelligenceConsent.isEnabled(app) || result.verdict != ScanVerdict.THREAT)
            return@withContext false
        val detectedHash = result.sha256?.lowercase()
            ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: return@withContext false

        var stagedFile: File? = null
        val apk = when {
            !result.sourceLocalPath.isNullOrBlank() && File(result.sourceLocalPath).isFile ->
                File(result.sourceLocalPath)
            !result.sourceUri.isNullOrBlank() -> {
                stagedFile = stageContentUri(result.sourceUri)
                stagedFile
            }
            !result.packageName.isNullOrBlank() -> runCatching {
                val info = app.packageManager.getApplicationInfo(result.packageName, 0)
                val path = info.sourceDir ?: info.publicSourceDir ?: return@runCatching null
                File(path)
            }.getOrNull()
            else -> null
        } ?: return@withContext false

        try {
            donateApk(apk, detectedHash)
        } finally {
            stagedFile?.delete()
        }
    }

    private suspend fun donateApk(apk: File, detectedHash: String): Boolean {
        if (!GlobalThreatIntelligenceConsent.isEnabled(app)) return false
        if (!detectedHash.matches(Regex("[0-9a-f]{64}")) ||
            !apk.isFile || !apk.canRead() || apk.length() !in 1..MAX_APK_BYTES) return false

        return try {
            if (sha256(apk) != detectedHash) return false
            val outcome = MachineLearningScanner(app).extractFeatureVector(apk)
            val vector = (outcome as? DrebinApkExtractor.Outcome.Features)?.vector ?: return false
            if (vector.size != FEATURE_COUNT || vector.any { it != 0f && it != 1f }) return false
            if (sha256(apk) != detectedHash) return false
            if (!GlobalThreatIntelligenceConsent.isEnabled(app)) return false

            val body = buildPayload(detectedHash, vector)
            val request = Request.Builder()
                .url(WORKER_ENDPOINT)
                .post(body.toRequestBody(JSON_MEDIA_TYPE))
                .build()
            client.newCall(request).execute().use { response ->
                if (response.isSuccessful) true
                else {
                    Log.w(TAG, "Anonymous threat contribution was rejected")
                    false
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            Log.w(TAG, "Anonymous threat contribution could not be completed")
            false
        } catch (_: LinkageError) {
            Log.w(TAG, "Anonymous threat contribution transport is unavailable")
            false
        }
    }

    private fun stageContentUri(uriValue: String): File? {
        val staged = runCatching { File.createTempFile("safe-mobile-ti-", ".apk", app.cacheDir) }
            .getOrNull() ?: return null
        return try {
            val input = app.contentResolver.openInputStream(Uri.parse(uriValue)) ?: run {
                staged.delete()
                return null
            }
            input.use { source ->
                FileOutputStream(staged).use { output ->
                    val buffer = ByteArray(32 * 1024)
                    var total = 0L
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > MAX_APK_BYTES) throw IOException("APK exceeds the bounded size")
                        output.write(buffer, 0, count)
                    }
                }
            }
            staged.takeIf { it.isFile && it.length() > 0L } ?: run {
                staged.delete()
                null
            }
        } catch (_: Exception) {
            staged.delete()
            null
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > MAX_APK_BYTES) throw IOException("APK exceeds the bounded size")
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    companion object {
        internal const val WORKER_ENDPOINT = "https://misty-fog-d936.navyask911.workers.dev"
        private const val FEATURE_COUNT = 215
        private const val MAX_APK_BYTES = 512L * 1024 * 1024
        private const val TAG = "SafeMobileGlobalTI"
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
        private val client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .callTimeout(15, TimeUnit.SECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

        internal fun buildPayload(sha256: String, vector: FloatArray): String {
            require(sha256.matches(Regex("[0-9a-f]{64}"))) { "Invalid SHA-256" }
            require(vector.size == FEATURE_COUNT && vector.all { it == 0f || it == 1f }) {
                "Expected exactly 215 binary features"
            }
            val features = JSONArray()
            vector.forEach { features.put(if (it == 1f) 1 else 0) }
            return JSONObject()
                .put("sha256", sha256)
                .put("features", features)
                .toString()
        }
    }
}
