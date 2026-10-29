package com.vibesync.antivirus.core.worker

import android.content.Context
import android.system.Os
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONArray
import org.json.JSONObject
import org.tensorflow.lite.DataType
import org.tensorflow.lite.Interpreter

/**
 * HTTPS-only, opt-in, read-only research distribution channel.
 * Models downloaded here are NEVER used by MachineLearningScanner: that scanner has
 * a separately reviewed 32-feature contract, while the training model needs a separately approved and validated schema.
 * There is no silent promotion from a loadable model into a trusted malware detector.
 */
class ModelUpdateWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    private val app = context.applicationContext
    private val preferences = app.getSharedPreferences("safe_mobile_ml_candidate", Context.MODE_PRIVATE)
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .callTimeout(100, TimeUnit.SECONDS)
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        try {
            if (!app.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
                    .getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)) {
                return@withContext Result.success()
            }
            stageIfNewer()
            Result.success()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: InvalidCandidate) {
            // Declined candidate (bad metadata, wrong model, bad digest, or unsafe redirect).
            Result.success()
        } catch (_: IOException) {
            // Only transport failures retry; never touch an already staged model.
            Result.retry()
        } catch (_: Exception) {
            Result.success()
        } finally {
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }

    private fun stageIfNewer() {
        val release = getLatestRelease() ?: return
        val tag = release.getString("tag_name")
        if (!ModelReleasePolicy.isNewer(tag, preferences.getString("candidate_version", null))) return
        val assets = ModelReleasePolicy.assets(release) ?: return

        val checksumAsset = assets.getValue(ModelReleasePolicy.SUMS)
        val checksumsBytes = getBytes(assetUrl(checksumAsset), 16384)
        verifyGitHubDigest(checksumAsset, sha256(checksumsBytes))
        val sums = ModelReleasePolicy.checksums(String(checksumsBytes, Charsets.UTF_8))
            ?: throw InvalidCandidate()

        fun verifiedTextAsset(name: String, limit: Int): ByteArray {
            val asset = assets.getValue(name)
            val bytes = getBytes(assetUrl(asset), limit)
            val sha = sha256(bytes)
            verifyGitHubDigest(asset, sha)
            if (bytes.size.toLong() != asset.optLong("size") || sums[name] != sha)
                throw InvalidCandidate()
            return bytes
        }

        val schemaBytes = verifiedTextAsset(ModelReleasePolicy.SCHEMA, 65536)
        // A new model cannot silently switch feature meanings on an existing APK.
        val appSchema = app.assets.open("feature_schema.json").use { it.readBytes() }
        if (sha256(schemaBytes) != sha256(appSchema)) throw InvalidCandidate()
        val reportBytes = verifiedTextAsset(ModelReleasePolicy.REPORT, 131072)
        // Keep CC BY 4.0 attribution in the update bundle for future owner review.
        val noticeBytes = verifiedTextAsset(ModelReleasePolicy.NOTICE, 32768)

        val directory = File(app.filesDir, "ml-research-candidates")
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("No internal model storage")
        val tmp = File.createTempFile("model-", ".part", directory)
        try {
            val modelAsset = assets.getValue(ModelReleasePolicy.MODEL)
            val declaredSize = modelAsset.optLong("size")
            if (declaredSize < 64 || declaredSize >= ModelReleasePolicy.MAX_BYTES) throw InvalidCandidate()
            val modelSha = getModelFile(assetUrl(modelAsset), tmp)
            if (tmp.length() != declaredSize || sums[ModelReleasePolicy.MODEL] != modelSha)
                throw InvalidCandidate()
            verifyGitHubDigest(modelAsset, modelSha)

            val schema = JSONObject(String(schemaBytes, Charsets.UTF_8))
            val report = JSONObject(String(reportBytes, Charsets.UTF_8))
            if (!ModelReleasePolicy.validatedResearchBundle(schema, report, modelSha, sha256(schemaBytes)))
                throw InvalidCandidate()
            inspectAndClose(tmp)

            // Commit only after the candidate and all metadata have passed verification.
            // Atomic rename occurs within the same app-private filesystem.
            val model = File(directory, "malware_model.tflite")
            Os.rename(tmp.absolutePath, model.absolutePath)
            // Scanner still reads ONLY its separately validated APK-signed model asset.
            if (!preferences.edit()
                    .putString("candidate_version", tag)
                    .putString("candidate_sha256", modelSha)
                    .putBoolean("production_active", false)
                    .commit()) throw IOException("Could not store version")
            // Keep a local attribution copy without affecting the atomic model update.
            File(directory, "DATASET_NOTICE.md").writeBytes(noticeBytes)
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    private fun inspectAndClose(file: File) {
        if (file.length() < 64 || file.length() >= ModelReleasePolicy.MAX_BYTES) throw InvalidCandidate()
        file.inputStream().use { source ->
            val header = ByteArray(8)
            if (source.read(header) != 8 ||
                String(header, 4, 4, Charsets.US_ASCII) != "TFL3") throw InvalidCandidate()
        }
        // The Interpreter must never remain open after worker verification.
        Interpreter(file, Interpreter.Options().setNumThreads(1)).use { interpreter ->
            interpreter.allocateTensors()
            if (interpreter.inputTensorCount != 1 || interpreter.outputTensorCount != 1)
                throw InvalidCandidate()
            val input = interpreter.getInputTensor(0)
            val output = interpreter.getOutputTensor(0)
            if (!input.shape().contentEquals(intArrayOf(1, ModelReleasePolicy.FEATURES)) ||
                !output.shape().contentEquals(intArrayOf(1, 1)) ||
                input.dataType() != DataType.FLOAT32 || output.dataType() != DataType.FLOAT32)
                throw InvalidCandidate()
            val result = Array(1) { FloatArray(1) }
            interpreter.run(arrayOf(FloatArray(ModelReleasePolicy.FEATURES)), result)
            if (!result[0][0].isFinite() || result[0][0] !in 0f..1f)
                throw InvalidCandidate()
        }
    }

    private fun getLatestRelease(): JSONObject? {
        // The training workflow publishes a prerelease, which /releases/latest excludes.
        // GitHub returns /releases in descending publication order. Prefer index 0, but
        // skip incomplete/draft bundles and never downgrade an installed version.
        val response = getApi(API + "/releases?per_page=20") ?: return null
        val list = JSONArray(String(response, Charsets.UTF_8))
        for (index in 0 until list.length()) {
            val release = list.optJSONObject(index) ?: continue
            if (ModelReleasePolicy.assets(release) != null) return release
        }
        return null
    }

    private fun getApi(url: String): ByteArray? {
        val parsed = url.toHttpUrl()
        if (parsed.scheme != "https" || parsed.host != "api.github.com" ||
            !parsed.encodedPath.startsWith("/repos/" + REPOSITORY + "/releases"))
            throw InvalidCandidate()
        call(parsed, false).use { response ->
            if (response.code == 404) return null
            if (!response.isSuccessful) throw IOException("Release API HTTP " + response.code)
            return bounded(response, 524288)
        }
    }

    private fun assetUrl(asset: JSONObject): HttpUrl {
        if (asset.optString("state") != "uploaded") throw InvalidCandidate()
        val url = asset.getString("browser_download_url").toHttpUrl()
        if (url.scheme != "https" || url.host != "github.com" ||
            !url.encodedPath.startsWith("/" + REPOSITORY + "/releases/download/") ||
            url.pathSegments.lastOrNull() != asset.optString("name") ||
            url.query != null) throw InvalidCandidate()
        return url
    }

    private fun call(initial: HttpUrl, asset: Boolean): Response {
        var current = initial
        repeat(5) {
            val request = Request.Builder().url(current)
                .header("User-Agent", "SafeMobile-Research-Model-Updater")
                .header("Accept", if (asset) "application/octet-stream" else "application/vnd.github+json")
                .build()
            val response = client.newCall(request).execute()
            if (!response.isRedirect) return response
            val location = response.header("Location")
            response.close()
            if (!asset || location == null) throw InvalidCandidate()
            val redirect = current.resolve(location) ?: throw InvalidCandidate()
            if (redirect.scheme != "https" || redirect.host !in setOf(
                    "github.com", "release-assets.githubusercontent.com",
                    "objects.githubusercontent.com")) throw InvalidCandidate()
            current = redirect
        }
        throw InvalidCandidate()
    }

    private fun getBytes(url: HttpUrl, limit: Int): ByteArray =
        call(url, true).use { response ->
            if (!response.isSuccessful) throw IOException("Asset HTTP " + response.code)
            bounded(response, limit)
        }

    private fun bounded(response: Response, max: Int): ByteArray {
        val body = response.body ?: throw IOException("Empty response body")
        if (body.contentLength() > max) throw InvalidCandidate()
        val data = ByteArrayOutputStream()
        body.byteStream().use { input ->
            val buffer = ByteArray(8192)
            var count = 0
            while (true) {
                val bytes = input.read(buffer)
                if (bytes < 0) break
                count += bytes
                if (count > max) throw InvalidCandidate()
                data.write(buffer, 0, bytes)
            }
        }
        return data.toByteArray()
    }

    private fun getModelFile(url: HttpUrl, destination: File): String =
        call(url, true).use { response ->
            if (!response.isSuccessful) throw IOException("Model HTTP " + response.code)
            val body = response.body ?: throw IOException("Empty model response")
            if (body.contentLength() >= ModelReleasePolicy.MAX_BYTES) throw InvalidCandidate()
            val digest = MessageDigest.getInstance("SHA-256")
            var count = 0L
            FileOutputStream(destination).use { output ->
                body.byteStream().use { input ->
                    val bytes = ByteArray(8192)
                    while (true) {
                        val length = input.read(bytes)
                        if (length < 0) break
                        count += length
                        if (count >= ModelReleasePolicy.MAX_BYTES) throw InvalidCandidate()
                        digest.update(bytes, 0, length)
                        output.write(bytes, 0, length)
                    }
                }
                output.fd.sync()
            }
            if (count < 64 || (body.contentLength() >= 0 && body.contentLength() != count))
                throw InvalidCandidate()
            digest.digest().joinToString("") { "%02x".format(it) }
        }

    private fun verifyGitHubDigest(asset: JSONObject, actualSha: String) {
        if (asset.optString("digest") != "sha256:" + actualSha) throw InvalidCandidate()
    }
    private fun sha256(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    private class InvalidCandidate : Exception()

    companion object {
        private const val REPOSITORY =
            "navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware"
        private const val API = "https://api.github.com/repos/" + REPOSITORY
    }
}
