package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import org.json.JSONArray
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import javax.net.ssl.HttpsURLConnection

/**
 * Downloads the owner-signed bundle only from this repository's public GitHub Releases.
 * MalwareBazaar is never contacted by the Android app, and scan data is never uploaded.
 */
class HashDatabaseSyncWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (!BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED ||
            BuildConfig.HASHDB_PUBLIC_KEY_B64.isBlank()
        ) return Result.failure()

        val app = applicationContext as? SafeMobileApp ?: return Result.failure()
        var temporary: java.io.File? = null
        return try {
            val asset = latestBundleAsset()
            temporary = java.io.File.createTempFile("safe-mobile-hashdb-", ".zip", applicationContext.cacheDir)
            download(asset.url, temporary, MAX_BUNDLE_BYTES)
            val capability = temporary.inputStream().use { input ->
                app.hashDatabaseManager.importBundle(input)
            }
            if (!capability.enabled) Result.failure() else {
                capability.version?.let { version ->
                    com.vibesync.antivirus.core.hashdb.HashDatabaseFreshness.recordVerifiedRelease(applicationContext, version, asset.publishedAt)
                }
                Result.success()
            }
        } catch (error: IOException) {
            android.util.Log.w(TAG, "GitHub hash database sync will retry after a network error.", error)
            Result.retry()
        } catch (error: Exception) {
            android.util.Log.e(TAG, "GitHub signed hash database update was rejected; current database remains active.", error)
            Result.failure()
        } finally {
            temporary?.delete()
        }
    }

    private data class BundleAsset(val url: String, val publishedAt: Long)

    private fun latestBundleAsset(): BundleAsset {
        val bytes = getBytes(RELEASES_API, API_HOSTS, MAX_RELEASES_JSON_BYTES)
        val releases = JSONArray(String(bytes, StandardCharsets.UTF_8))
        var latestPublished = ""
        var latestUrl: String? = null
        for (index in 0 until releases.length()) {
            val release = releases.optJSONObject(index) ?: continue
            if (release.optBoolean("draft", true) || release.optBoolean("prerelease", true)) continue
            val assets = release.optJSONArray("assets") ?: continue
            for (assetIndex in 0 until assets.length()) {
                val asset = assets.optJSONObject(assetIndex) ?: continue
                if (asset.optString("name") != BUNDLE_ASSET) continue
                val candidate = asset.optString("browser_download_url")
                val published = release.optString("published_at")
                if (published > latestPublished && isReleaseAssetUrl(candidate)) {
                    latestPublished = published
                    latestUrl = candidate
                }
            }
        }
        val url = latestUrl ?: throw IOException("No published GitHub Release contains the signed database bundle.")
        val publishedAt = runCatching { java.time.Instant.parse(latestPublished).toEpochMilli() }.getOrNull()
            ?: throw IOException("GitHub database release omitted a valid publication time.")
        return BundleAsset(url, publishedAt)
    }

    private fun isReleaseAssetUrl(value: String): Boolean = runCatching {
        val url = URL(value)
        url.protocol.equals("https", ignoreCase = true) &&
            url.host.equals("github.com", ignoreCase = true) &&
            url.path.startsWith(RELEASE_ASSET_PATH)
    }.getOrDefault(false)

    private fun download(url: String, destination: java.io.File, limit: Int) {
        val bytes = getBytes(url, ASSET_HOSTS, limit)
        destination.outputStream().use { output ->
            output.write(bytes)
            output.flush()
        }
    }

    /** Follows only bounded HTTPS redirects to GitHub's release-asset hosts. */
    private fun getBytes(startUrl: String, allowedHosts: Set<String>, limit: Int): ByteArray {
        var url = URL(startUrl)
        repeat(MAX_REDIRECTS + 1) { redirectCount ->
            require(
                url.protocol.equals("https", ignoreCase = true) &&
                    url.host.lowercase(java.util.Locale.ROOT) in allowedHosts
            ) { "Refusing non-GitHub or non-HTTPS database URL." }

            val connection = url.openConnection() as? HttpsURLConnection
                ?: throw IOException("HTTPS connection was unavailable.")
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = CONNECT_TIMEOUT_MS
                connection.readTimeout = READ_TIMEOUT_MS
                connection.useCaches = false
                connection.requestMethod = "GET"
                connection.setRequestProperty("User-Agent", USER_AGENT)
                connection.setRequestProperty(
                    "Accept",
                    if (url.host.equals(API_HOST, ignoreCase = true)) "application/vnd.github+json"
                    else "application/octet-stream"
                )
                val code = connection.responseCode
                if (code in REDIRECT_CODES) {
                    if (redirectCount >= MAX_REDIRECTS) throw IOException("Too many GitHub release redirects.")
                    val location = connection.getHeaderField("Location")
                        ?: throw IOException("GitHub redirect omitted Location.")
                    url = URL(url, location)
                    return@repeat
                }
                if (code == 429 || code >= 500) throw IOException("GitHub returned retryable HTTP $code.")
                if (code !in 200..299) throw GitHubHttpException(code)
                val length = connection.contentLengthLong
                require(length < 0L || length <= limit.toLong()) { "GitHub response exceeded its size limit." }
                return connection.inputStream.use { readBounded(it, limit) }
            } finally {
                connection.disconnect()
            }
        }
        throw IOException("GitHub redirect limit was exceeded.")
    }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(limit, 8192))
        val buffer = ByteArray(16 * 1024)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            total += count
            require(total <= limit) { "GitHub response exceeded its size limit." }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private class GitHubHttpException(val code: Int) : Exception("GitHub returned HTTP $code.")

    companion object {
        private const val TAG = "HashDatabaseSync"
        private const val API_HOST = "api.github.com"
        private const val RELEASES_API =
            "https://api.github.com/repos/navyask911/VibeSync-SafeMobile-Antivirus/releases?per_page=100"
        private const val BUNDLE_ASSET = "safe-mobile-hashdb.bundle.zip"
        private const val RELEASE_ASSET_PATH =
            "/navyask911/VibeSync-SafeMobile-Antivirus/releases/download/"
        private const val MAX_RELEASES_JSON_BYTES = 1_500_000
        private const val MAX_BUNDLE_BYTES = 18 * 1024 * 1024
        private const val MAX_REDIRECTS = 3
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 45_000
        private const val USER_AGENT = "SafeMobile-Antivirus-Android"
        private val API_HOSTS = setOf("api.github.com")
        private val ASSET_HOSTS = setOf(
            "github.com", "objects.githubusercontent.com",
            "release-assets.githubusercontent.com", "github-releases.githubusercontent.com"
        )
        private val REDIRECT_CODES = setOf(
            HttpURLConnection.HTTP_MOVED_PERM, HttpURLConnection.HTTP_MOVED_TEMP,
            HttpURLConnection.HTTP_SEE_OTHER, 307, 308
        )
    }
}

