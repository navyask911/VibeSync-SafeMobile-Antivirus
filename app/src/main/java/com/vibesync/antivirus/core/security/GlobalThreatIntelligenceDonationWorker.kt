package com.vibesync.antivirus.core.security

import android.content.Context
import android.util.Log
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.Data
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CancellationException

/**
 * Persisted, network-constrained delivery for an individually user-approved sample.
 * Only a SHA-256, local source locator and event key are stored in WorkManager input;
 * the source locator is never included in the HTTP payload.
 */
class GlobalThreatIntelligenceDonationWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val sourceType = when {
            !inputData.getString(KEY_SOURCE_LOCAL_PATH).isNullOrBlank() -> "local-file"
            !inputData.getString(KEY_SOURCE_URI).isNullOrBlank() -> "document-uri"
            !inputData.getString(KEY_PACKAGE_NAME).isNullOrBlank() -> "installed-package"
            else -> "missing"
        }
        val hashPrefix = inputData.getString(KEY_SHA256)?.take(12) ?: "missing"
        Log.i(TAG, "Donation worker started (source=$sourceType, sha256=$hashPrefix…)")
        val oneTimeConsent = inputData.getBoolean(KEY_ONE_TIME_APPROVED, false)
        if (!oneTimeConsent && !GlobalThreatIntelligenceConsent.isEnabled(applicationContext)) {
            Log.i(TAG, "Donation consent is off; dropping queued contribution")
            return Result.success()
        }

        val sha256 = inputData.getString(KEY_SHA256)
            ?.lowercase()
            ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) }
            ?: run {
                Log.e(TAG, "Donation worker stopped: missing or invalid SHA-256 input")
                return Result.failure()
            }
        val sourceLocalPath = inputData.getString(KEY_SOURCE_LOCAL_PATH)
        val sourceUri = inputData.getString(KEY_SOURCE_URI)
        val packageName = inputData.getString(KEY_PACKAGE_NAME)
        if (sourceLocalPath.isNullOrBlank() && sourceUri.isNullOrBlank() && packageName.isNullOrBlank()) {
            Log.e(TAG, "Donation worker stopped: queued item has no sample source")
            return Result.failure()
        }

        val sample = ScanResult(
            packageOrPath = sourceLocalPath ?: sourceUri ?: packageName.orEmpty(),
            displayName = "User-approved threat sample",
            sha256 = sha256,
            md5 = null,
            verdict = ScanVerdict.THREAT,
            reasons = emptyList(),
            durationMs = 0L,
            packageName = packageName,
            sourceUri = sourceUri,
            sourceLocalPath = sourceLocalPath,
            threatEventId = inputData.getString(KEY_EVENT_ID)
        )

        return try {
            if (GlobalThreatIntelligenceDonor(applicationContext).donateScanResult(sample, oneTimeConsent)) {
                Log.i(TAG, "Background threat contribution completed")
                Result.success()
            } else {
                Log.w(TAG, "Background threat contribution was not eligible or was rejected")
                Result.failure()
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: IOException) {
            // WorkManager waits for connectivity and retries transient transport/server failures.
            Log.e(TAG, "Background Cloudflare donation failed; WorkManager will retry", error)
            Result.retry()
        } catch (error: Exception) {
            Log.e(TAG, "Background Cloudflare donation failed permanently", error)
            Result.failure()
        }
    }

    companion object {
        internal const val KEY_SHA256 = "donation_sha256"
        internal const val KEY_SOURCE_LOCAL_PATH = "donation_source_local_path"
        internal const val KEY_SOURCE_URI = "donation_source_uri"
        internal const val KEY_PACKAGE_NAME = "donation_package_name"
        internal const val KEY_EVENT_ID = "donation_event_id"
        internal const val KEY_ONE_TIME_APPROVED = "donation_one_time_approved"
        internal const val UNIQUE_WORK_PREFIX = "safe_mobile_global_threat_donation"
        private const val TAG = "Donation"
    }
}

/** Enqueues work before the dialog closes; it is not owned by the Compose lifecycle. */
internal object GlobalThreatIntelligenceDonationScheduler {
    private const val TAG = "Donation"

    fun enqueueInstalledPackage(
        context: Context,
        packageName: String,
        detectedSha256: String,
        eventId: String?,
        oneTimeConsent: Boolean = false
    ): Boolean {
        val normalizedPackage = packageName.takeIf {
            it.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))
        } ?: run {
            Log.e(TAG, "Installed-package donation refused: invalid local package reference")
            return false
        }
        val normalizedHash = detectedSha256.lowercase()
            .takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: run {
                Log.e(TAG, "Installed-package donation refused: invalid SHA-256")
                return false
            }
        val sample = ScanResult(
            packageOrPath = normalizedPackage,
            displayName = "User-approved threat sample",
            sha256 = normalizedHash,
            md5 = null,
            verdict = ScanVerdict.THREAT,
            reasons = emptyList(),
            durationMs = 0L,
            packageName = normalizedPackage,
            threatEventId = eventId
        )
        return if (oneTimeConsent) enqueueOnce(context, sample) else enqueue(context, sample)
    }

    fun enqueue(context: Context, result: ScanResult): Boolean = enqueueInternal(context, result, oneTimeConsent = false)

    /** Queues exactly one sample after a distinct user confirmation without changing the global setting. */
    fun enqueueOnce(context: Context, result: ScanResult): Boolean = enqueueInternal(context, result, oneTimeConsent = true)

    private fun enqueueInternal(context: Context, result: ScanResult, oneTimeConsent: Boolean): Boolean {
        val app = context.applicationContext
        if (!oneTimeConsent && !GlobalThreatIntelligenceConsent.isEnabled(app)) {
            Log.w(TAG, "Donation queue refused: master contribution consent is off")
            return false
        }
        if (result.verdict != ScanVerdict.THREAT) {
            Log.w(TAG, "Donation queue refused: sample is not a confirmed THREAT")
            return false
        }
        val sha256 = result.sha256?.lowercase()
            ?.takeIf { it.matches(Regex("[0-9a-f]{64}")) } ?: run {
                Log.e(TAG, "Donation queue refused: confirmed threat has no valid SHA-256")
                return false
            }
        if (result.sourceLocalPath.isNullOrBlank() &&
            result.sourceUri.isNullOrBlank() &&
            result.packageName.isNullOrBlank()
        ) {
            Log.e(TAG, "Donation queue refused: confirmed threat has no local source reference")
            return false
        }

        return try {
            val eventId = result.threatEventId
                ?.takeIf { it.matches(Regex("[A-Za-z0-9_-]{1,80}")) }
                ?: sha256
            val input = Data.Builder()
                .putString(GlobalThreatIntelligenceDonationWorker.KEY_SHA256, sha256)
                 .putString(GlobalThreatIntelligenceDonationWorker.KEY_EVENT_ID, eventId)
                .putBoolean(GlobalThreatIntelligenceDonationWorker.KEY_ONE_TIME_APPROVED, oneTimeConsent)
            result.sourceLocalPath?.let {
                input.putString(GlobalThreatIntelligenceDonationWorker.KEY_SOURCE_LOCAL_PATH, it)
            }
            result.sourceUri?.let {
                input.putString(GlobalThreatIntelligenceDonationWorker.KEY_SOURCE_URI, it)
            }
            result.packageName?.let {
                input.putString(GlobalThreatIntelligenceDonationWorker.KEY_PACKAGE_NAME, it)
            }

            val request = OneTimeWorkRequestBuilder<GlobalThreatIntelligenceDonationWorker>()
                .setInputData(input.build())
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .addTag(GlobalThreatIntelligenceDonationWorker.UNIQUE_WORK_PREFIX)
                .build()
            val operation = WorkManager.getInstance(app).enqueueUniqueWork(
                "${GlobalThreatIntelligenceDonationWorker.UNIQUE_WORK_PREFIX}-$eventId",
                ExistingWorkPolicy.KEEP,
                request
            )
            operation.result.addListener(
                {
                    try {
                        operation.result.get()
                        Log.i(TAG, "WorkManager persisted the approved donation request (sha256=${sha256.take(12)}…)")
                    } catch (error: Exception) {
                        Log.e(TAG, "WorkManager could not persist the approved donation request", error)
                    }
                },
                java.util.concurrent.Executor { command -> command.run() }
            )
            Log.d(TAG, "${if (oneTimeConsent) "One-time approved" else "Opted-in"} threat contribution queued (source=local-only, sha256=${sha256.take(12)}…)")
            true
        } catch (error: Exception) {
            Log.e(TAG, "Could not queue user-approved threat contribution", error)
            false
        }
    }
}
