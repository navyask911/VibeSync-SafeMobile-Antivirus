package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.room.withTransaction
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.BackoffPolicy
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import com.vibesync.antivirus.data.local.ThreatFeedStagingEntity
import com.vibesync.antivirus.data.local.MalwareHashEntity
import com.vibesync.antivirus.data.local.ThreatDatabase
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.util.UUID
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.security.DigestInputStream
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.zip.GZIPInputStream

class ThreatFeedSyncWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext as? SafeMobileApp ?: return Result.failure()
        val database = app.database
        val store = ThreatFeedConfigStore(applicationContext)
        if (!BuildConfig.OPTIONAL_FEED_ENABLED || !store.isSyncEnabled()) return Result.success()
        if (!BuildConfig.FEED_MANIFEST_KEY_CONFIGURED) return Result.failure()
        val config = runCatching { store.load() }.getOrElse { return Result.failure() }
        if (config.url.isBlank()) return Result.success()
        if (config.requestMode != ThreatFeedRequestMode.GET) return Result.failure()

        val uri = runCatching { URI(config.url) }.getOrElse { return Result.failure() }
        val sourceHost = uri.host?.lowercase(Locale.ROOT) ?: return Result.failure()
        val sourceKey = sha256(config.url)
        val stateDao = database.threatFeedSyncStateDao()
        val hashDao = database.malwareHashDao()
        val stagingDao = database.threatFeedStagingDao()
        val previousState = runCatching { stateDao.get(sourceKey) }.getOrNull()
        val attemptedAt = System.currentTimeMillis()
        val importId = UUID.randomUUID().toString()
        runCatching { stagingDao.deleteStaleBefore(attemptedAt - STAGING_RETENTION_MS) }
        val runningState = ThreatFeedSyncStateEntity(
            sourceKey = sourceKey,
            sourceHost = sourceHost,
            lastAttemptAt = attemptedAt,
            lastSuccessAt = previousState?.lastSuccessAt,
            status = STATUS_RUNNING,
            lastError = null,
            lastImportedCount = previousState?.lastImportedCount ?: 0,
            etag = previousState?.etag,
            lastModified = previousState?.lastModified,
            feedVersion = previousState?.feedVersion ?: 0L,
            feedManifestSha256 = previousState?.feedManifestSha256
        )
        database.withTransaction { stateDao.upsert(runningState) }

        var connection: HttpURLConnection? = null
        return try {
            connection = openFeedConnection(config, previousState?.etag)
            val code = connection.responseCode
            if (code == HttpURLConnection.HTTP_NOT_MODIFIED) {
                if ((previousState?.feedVersion ?: 0L) <= 0L || previousState?.feedManifestSha256.isNullOrBlank()) {
                    throw FeedConfigurationException("Unverified 304 response rejected because no signed feed version has been accepted.")
                }
                val now = System.currentTimeMillis()
                database.withTransaction {
                    stateDao.upsert(runningState.copy(
                        lastAttemptAt = now,
                        lastSuccessAt = now,
                        status = STATUS_SUCCESS,
                        lastError = null,
                        lastImportedCount = 0,
                        etag = connection.getHeaderField("ETag") ?: previousState?.etag,
                        lastModified = connection.getHeaderField("Last-Modified") ?: previousState?.lastModified
                    ))
                }
                return Result.success()
            }
            if (code == 401 || code == 403) throw FeedConfigurationException("The provider rejected the feed credentials.")
            if (code == 408 || code == 429 || code >= 500) throw FeedTransientException("The feed endpoint is temporarily unavailable (HTTP $code).")
            if (code !in 200..299) throw FeedConfigurationException("The feed endpoint returned HTTP $code.")

            val signedManifest = SignedFeedManifestVerifier.verifyHeaders(
                connection.getHeaderField(SignedFeedManifestVerifier.MANIFEST_HEADER),
                connection.getHeaderField(SignedFeedManifestVerifier.SIGNATURE_HEADER),
                BuildConfig.FEED_MANIFEST_PUBLIC_KEY_B64
            )
            SignedFeedManifestVerifier.validateSourceAndVersion(
                signedManifest, sourceKey, previousState?.feedVersion ?: 0L
            )

            val remoteFormat = when (config.format) {
                ThreatFeedFormat.JSON -> ThreatFeedFormat.JSON
                ThreatFeedFormat.CSV -> ThreatFeedFormat.CSV
                ThreatFeedFormat.AUTO -> when {
                    connection.contentType.orEmpty().contains("json", ignoreCase = true) -> ThreatFeedFormat.JSON
                    connection.contentType.orEmpty().contains("csv", ignoreCase = true) -> ThreatFeedFormat.CSV
                    config.url.substringBefore('?').endsWith(".csv", ignoreCase = true) -> ThreatFeedFormat.CSV
                    else -> ThreatFeedFormat.JSON
                }
            }
            val raw = connection.inputStream
            val decoded = if (connection.contentEncoding.equals("gzip", ignoreCase = true)) GZIPInputStream(raw, IO_BUFFER_SIZE) else raw
            val payloadDigest = MessageDigest.getInstance("SHA-256")
            val bounded = LimitedInputStream(DigestInputStream(decoded, payloadDigest), MAX_FEED_BYTES)
            val parser = ThreatFeedParser()
            val parsedCount = parser.parse(bounded, remoteFormat, sourceHost) { batch ->
                val staged = batch.map { row ->
                    ThreatFeedStagingEntity(
                        importId = importId,
                        indicatorKey = row.indicatorKey,
                        sha256Hash = row.sha256Hash,
                        md5Hash = row.md5Hash,
                        sha1Hash = row.sha1Hash,
                        fileSize = row.fileSize,
                        iocValue = row.iocValue,
                        iocType = row.iocType,
                        threatName = row.threatName,
                        source = row.source,
                        firstSeenAt = row.firstSeenAt,
                        lastSeenAt = row.lastSeenAt,
                        updatedAt = row.updatedAt,
                        stagedAt = attemptedAt
                    )
                }
                database.withTransaction { stagingDao.upsertBatch(staged) }
            }
            if (config.updateMode == ThreatFeedUpdateMode.AUTHORITATIVE_SNAPSHOT) {
                requireNonEmptyAuthoritativeSnapshot(parsedCount)
            }
            val actualPayloadSha256 = payloadDigest.digest().joinToString("") { "%02x".format(it) }
            SignedFeedManifestVerifier.validatePayload(signedManifest, actualPayloadSha256)
            val now = System.currentTimeMillis()
            database.withTransaction {
                // Replace a source snapshot only after the entire non-empty response parsed.
                // Deletion, staged-row promotion, cleanup, and success state commit atomically.
                if (config.updateMode == ThreatFeedUpdateMode.AUTHORITATIVE_SNAPSHOT) {
                    hashDao.deleteSource(sourceHost)
                }
                var afterIndicatorKey = ""
                while (true) {
                    val stagedBatch = stagingDao.nextBatch(importId, afterIndicatorKey, STAGING_BATCH_SIZE)
                    if (stagedBatch.isEmpty()) break
                    hashDao.upsertBatch(stagedBatch.map { it.toMalwareHashEntity() })
                    afterIndicatorKey = stagedBatch.last().indicatorKey
                }
                val importedCount = stagingDao.countForImport(importId)
                stagingDao.deleteForImport(importId)
                stateDao.upsert(runningState.copy(
                    lastAttemptAt = now,
                    lastSuccessAt = now,
                    status = STATUS_SUCCESS,
                    lastError = null,
                    lastImportedCount = importedCount,
                    etag = connection.getHeaderField("ETag") ?: previousState?.etag,
                    lastModified = connection.getHeaderField("Last-Modified") ?: previousState?.lastModified,
                    feedVersion = signedManifest.version,
                    feedManifestSha256 = signedManifest.rawManifestSha256
                ))
            }
            Result.success()
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            withContext(NonCancellable) {
                storeFailure(
                    database, runningState, importId,
                    status = STATUS_RETRY,
                    message = "Feed synchronization was cancelled; active indicators were not changed."
                )
            }
            throw cancelled
        } catch (error: FeedConfigurationException) {
            storeFailure(database, runningState, importId, status = STATUS_FAILED, message = error.message)
            Result.failure()
        } catch (error: FeedParseException) {
            storeFailure(database, runningState, importId, status = STATUS_FAILED, message = error.message)
            Result.failure()
        } catch (error: FeedSizeLimitException) {
            storeFailure(database, runningState, importId, status = STATUS_FAILED, message = "Feed exceeded the maximum supported size.")
            Result.failure()
        } catch (error: FeedTransientException) {
            storeFailure(database, runningState, importId, status = STATUS_RETRY, message = error.message)
            Result.retry()
        } catch (error: IOException) {
            storeFailure(database, runningState, importId, status = STATUS_RETRY, message = "Network read failed; existing local indicators were retained.")
            Result.retry()
        } catch (_: Exception) {
            storeFailure(database, runningState, importId, status = STATUS_FAILED, message = "Feed synchronization failed; existing local indicators were retained.")
            Result.failure()
        } finally {
            connection?.disconnect()
        }
    }

    private suspend fun storeFailure(
        database: ThreatDatabase,
        running: ThreatFeedSyncStateEntity,
        importId: String,
        status: String,
        message: String?
    ) {
        runCatching {
            database.withTransaction {
                database.threatFeedStagingDao().deleteForImport(importId)
                database.threatFeedSyncStateDao().upsert(running.copy(
                    lastAttemptAt = System.currentTimeMillis(),
                    status = status,
                    lastError = message?.take(220)
                ))
            }
        }
    }

    private fun openFeedConnection(
        config: ThreatFeedConfiguration,
        etag: String?
    ): HttpURLConnection {
        var current = URI(config.url)
        repeat(MAX_REDIRECTS + 1) { hop ->
            if (!current.scheme.equals("https", ignoreCase = true) || current.host.isNullOrBlank()) {
                throw FeedConfigurationException("Feed URL or redirect must use HTTPS.")
            }
            val connection = current.toURL().openConnection() as? HttpURLConnection
                ?: throw FeedConfigurationException("Unsupported feed connection.")
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.setRequestProperty("Accept", "application/json, text/csv, */*")
            connection.setRequestProperty("Accept-Encoding", "gzip")
            connection.setRequestProperty("User-Agent", "SafeMobile-ThreatFeed/1.0")
            if (config.authKey.isNotBlank()) connection.setRequestProperty("Auth-Key", config.authKey)
            if (hop == 0 && !etag.isNullOrBlank()) connection.setRequestProperty("If-None-Match", etag)

            // Signed updates are GET-only and never transmit scan data.
            connection.requestMethod = "GET"

            val code = connection.responseCode
            if (code in 300..399) {
                val location = connection.getHeaderField("Location")
                connection.disconnect()
                if (location.isNullOrBlank() || hop >= MAX_REDIRECTS) {
                    throw FeedConfigurationException("Feed endpoint redirected too many times.")
                }
                val next = current.resolve(location)
                if (!next.scheme.equals("https", ignoreCase = true)) {
                    throw FeedConfigurationException("Insecure feed redirects are blocked.")
                }
                if (config.authKey.isNotBlank() && !next.host.equals(current.host, ignoreCase = true)) {
                    throw FeedConfigurationException("Cross-host redirects are blocked when an Auth-Key is set.")
                }
                current = next
            } else {
                return connection
            }
        }
        throw FeedConfigurationException("Could not resolve the feed endpoint.")
    }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    private class LimitedInputStream(input: InputStream, private val maxBytes: Long) : FilterInputStream(input) {
        private var count = 0L
        override fun read(): Int {
            val value = super.read()
            if (value >= 0) addCount(1)
            return value
        }
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            val read = super.read(buffer, offset, length)
            if (read > 0) addCount(read.toLong())
            return read
        }
        private fun addCount(amount: Long) {
            count += amount
            if (count > maxBytes) throw FeedSizeLimitException()
        }
    }

    companion object {
        const val UNIQUE_PERIODIC_NAME = "safe_mobile_threat_feed_periodic"
        const val UNIQUE_NOW_NAME = "safe_mobile_threat_feed_manual"
        private const val STATUS_RUNNING = "RUNNING"
        private const val STATUS_SUCCESS = "SUCCESS"
        private const val STATUS_RETRY = "RETRY"
        private const val STATUS_FAILED = "FAILED"
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 30_000
        private const val MAX_FEED_BYTES = 128L * 1024L * 1024L
        private const val IO_BUFFER_SIZE = 64 * 1024
        private const val MAX_REDIRECTS = 3
        private const val STAGING_BATCH_SIZE = 500
        private const val STAGING_RETENTION_MS = 7L * 24L * 60L * 60L * 1000L
    }
}

private fun ThreatFeedStagingEntity.toMalwareHashEntity() = MalwareHashEntity(
    indicatorKey = indicatorKey,
    sha256Hash = sha256Hash,
    md5Hash = md5Hash,
    sha1Hash = sha1Hash,
    fileSize = fileSize,
    iocValue = iocValue,
    iocType = iocType,
    threatName = threatName,
    source = source,
    firstSeenAt = firstSeenAt,
    lastSeenAt = lastSeenAt,
    updatedAt = updatedAt
)

object ThreatFeedSyncScheduler {
    private fun constraints() = Constraints.Builder()
        .setRequiredNetworkType(NetworkType.UNMETERED)
        .setRequiresCharging(true)
        .build()

    fun ensurePeriodic(context: Context) {
        val manager = WorkManager.getInstance(context.applicationContext)
        if (!BuildConfig.OPTIONAL_FEED_ENABLED || !ThreatFeedConfigStore(context).isSyncEnabled() ||
            !BuildConfig.FEED_MANIFEST_KEY_CONFIGURED || !ThreatFeedConfigStore(context).isConfigured()) {
            manager.cancelUniqueWork(ThreatFeedSyncWorker.UNIQUE_NOW_NAME)
            manager.cancelUniqueWork(ThreatFeedSyncWorker.UNIQUE_PERIODIC_NAME)
            return
        }
        val request = PeriodicWorkRequestBuilder<ThreatFeedSyncWorker>(24, TimeUnit.HOURS)
            .setConstraints(constraints())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        manager.enqueueUniquePeriodicWork(
            ThreatFeedSyncWorker.UNIQUE_PERIODIC_NAME,
            ExistingPeriodicWorkPolicy.UPDATE,
            request
        )
    }

    fun enqueueNow(context: Context) {
        if (!BuildConfig.OPTIONAL_FEED_ENABLED || !BuildConfig.FEED_MANIFEST_KEY_CONFIGURED ||
            !ThreatFeedConfigStore(context).isSyncEnabled() || !ThreatFeedConfigStore(context).isConfigured()) return
        val request = OneTimeWorkRequestBuilder<ThreatFeedSyncWorker>()
            .setConstraints(constraints())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
            .build()
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            ThreatFeedSyncWorker.UNIQUE_NOW_NAME,
            ExistingWorkPolicy.KEEP,
            request
        )
    }
}

class FeedConfigurationException(message: String) : Exception(message)
class FeedTransientException(message: String) : IOException(message)
class FeedSizeLimitException : IOException("Threat feed exceeded the maximum size.")
