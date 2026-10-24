package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.hashdb.HashDatabaseConfigStore
import java.io.IOException
import java.net.URI
import javax.net.ssl.HttpsURLConnection

/** Downloads a user-configured signed database bundle only. This worker never uploads scan data. */
class HashDatabaseSyncWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (!BuildConfig.OPTIONAL_FEED_ENABLED || !BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED) {
            return Result.success()
        }
        val config = runCatching { HashDatabaseConfigStore(applicationContext).read() }.getOrNull()
            ?: return Result.failure()
        if (!config.enabled || config.url.isBlank()) return Result.success()
        val uri = runCatching { URI(config.url) }.getOrNull() ?: return Result.failure()
        if (!uri.scheme.equals("https", ignoreCase = true) || uri.host.isNullOrBlank() ||
            uri.rawUserInfo != null || uri.fragment != null) return Result.failure()

        var connection: HttpsURLConnection? = null
        return try {
            connection = uri.toURL().openConnection() as? HttpsURLConnection ?: return Result.failure()
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 30_000
            connection.useCaches = false
            connection.requestMethod = "GET"
            connection.doOutput = false
            val code = connection.responseCode
            when {
                code in 200..299 -> {
                    val app = applicationContext as? SafeMobileApp ?: return Result.failure()
                    connection.inputStream.use { app.hashDatabaseManager.importBundle(it) }
                    Result.success()
                }
                code == 429 || code >= 500 -> Result.retry()
                else -> Result.failure()
            }
        } catch (_: IOException) {
            Result.retry()
        } catch (_: SecurityException) {
            Result.failure()
        } catch (_: IllegalArgumentException) {
            Result.failure()
        } catch (_: Exception) {
            Result.failure()
        } finally {
            connection?.disconnect()
        }
    }
}
