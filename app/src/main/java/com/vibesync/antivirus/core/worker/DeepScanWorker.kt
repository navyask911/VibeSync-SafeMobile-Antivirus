package com.vibesync.antivirus.core.worker

import android.content.Context
import android.os.SystemClock
import android.util.Log
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.engine.ScanCompletionSummary
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.sync.withLock

/** Periodic full-device scan promoted to an explicit foreground WorkManager task. */
class DeepScanWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun getForegroundInfo(): ForegroundInfo =
        ScanForegroundNotifications.create(applicationContext, ScanForegroundNotifications.notificationId(id))

    override suspend fun doWork(): Result {
        Log.d("ScanDebug", "Worker STARTED for: $tags")
        Log.d("ScanDebug", "Worker attempt=$runAttemptCount id=$id")
        return try {
            ScanExecutionCoordinator.mutex.withLock {
                val safeApp = applicationContext as? SafeMobileApp
                    ?: throw IllegalStateException("SafeMobileApp application is unavailable.")
                val sessionId = id.toString()
                try {
                    val lastCompletedAt = safeApp.repository.latestCompletedScanAt()
                    val latestSummary = safeApp.repository.loadScanSummary()
                    val wallNow = System.currentTimeMillis()
                    if (ScanPublishPolicy.shouldDeduplicate(
                            lastCompletedAt = lastCompletedAt,
                            now = wallNow,
                            pendingRetries = latestSummary?.pendingRetries ?: 0,
                            runAttemptCount = runAttemptCount,
                            cooldownMs = DUPLICATE_COOLDOWN_MS
                        )
                    ) {
                        Log.i("ScanDebug", "scan_dedup_skipped reason=recent_completed_clean_session ageMs=\${wallNow - (lastCompletedAt ?: wallNow)}")
                        return@withLock Result.success()
                    }

                    setForeground(getForegroundInfo())
                    // Reuse this WorkRequest's checkpoints across retry attempts.
                    // NOT_SCANNED rows are excluded by scanSessionItemKeys() and reprocessed.
                    safeApp.repository.startScanSession(sessionId, "PERIODIC_DEEP_SCAN", isManual = false)
                    val startedElapsed = SystemClock.elapsedRealtime()
                    safeApp.repository.deepScan(sessionId)
                    safeApp.repository.addScanSessionElapsedMs(
                        sessionId, (SystemClock.elapsedRealtime() - startedElapsed).coerceAtLeast(0L)
                    )

                    val state = safeApp.repository.scanSessionState(sessionId)
                    val publish = safeApp.repository.scanPublishSummary(sessionId)
                    Log.i("ScanDebug", "Total publish failures: ${publish.failureCount} / ${publish.totalPackages}")
                    val persisted = state?.scannedItems ?: 0
                    if (ScanPublishPolicy.shouldFail(persisted, publish.failureCount)) {
                        safeApp.repository.failScanSession(sessionId)
                        safeApp.repository.clearScanPublishSummary(sessionId)
                        Log.e("ScanDebug", "Rejecting deep scan completion: persisted=$persisted, publishFailures=${publish.failureCount}")
                        return@withLock Result.failure()
                    }

                    val rows = safeApp.repository.loadScanSessionResults(sessionId)
                        .filter { safeApp.repository.isReviewableResult(it) }
                    val completedAt = System.currentTimeMillis()
                    val summary = ScanCompletionSummary.from(
                        results = rows,
                        processed = persisted,
                        now = completedAt,
                        skippedFiles = safeApp.repository.skippedSafFileCount(sessionId),
                        startedAt = safeApp.repository.scanSessionStartedAt(sessionId) ?: completedAt,
                        elapsedMsOverride = safeApp.repository.scanSessionElapsedMs(sessionId),
                        enumeratedPackages = state?.enumeratedItems ?: 0,
                        queuedPackages = state?.eligibleItems ?: 0,
                        excludedPackages = state?.excludedItems ?: 0
                    ).copy(signedDefinitionsUsed = safeApp.repository.currentHashDatabaseCapability()?.enabled == true)
                    safeApp.repository.saveScanSummary(summary)

                    if (summary.pendingRetries > 0) {
                        safeApp.repository.clearScanPublishSummary(sessionId)
                        if (ScanPublishPolicy.shouldRetry(summary.pendingRetries, runAttemptCount, MAX_RETRIES)) {
                            safeApp.repository.interruptScanSession(sessionId)
                            Log.w("ScanDebug", "scan_retry scheduled pendingRetries=${summary.pendingRetries} attempt=$runAttemptCount sessionId=$sessionId")
                            return@withLock Result.retry()
                        }
                        // The run is terminal after its retry budget, but keep the partial
                        // report visible so pending applications are not hidden from Scan & Lab.
                        safeApp.repository.completeScanSession(sessionId, completedAt)
                        Log.e("ScanDebug", "scan_retry_exhausted pendingRetries=${summary.pendingRetries} attempt=$runAttemptCount")
                        return@withLock Result.failure()
                    }

                    safeApp.repository.completeScanSession(sessionId, completedAt)
                    safeApp.repository.clearScanPublishSummary(sessionId)
                    Log.i(
                        "ScanDebug",
                        "scan_report completedApps=${summary.completedAppCount} cacheHits=${summary.cachedAppCount} " +
                            "scannedBytes=${summary.scannedApkBytes} elapsedMs=${summary.elapsedMs}"
                    )
                    val result = Result.success()
                    Log.d("ScanDebug", "Worker FINISHED with result: $result")
                    result
                } catch (cancelled: CancellationException) {
                    runCatching { safeApp.repository.interruptScanSession(sessionId) }
                    runCatching { safeApp.repository.clearScanPublishSummary(sessionId) }
                    throw cancelled
                } catch (error: Exception) {
                    val publish = runCatching { safeApp.repository.scanPublishSummary(sessionId) }.getOrNull()
                    if (publish != null) {
                        Log.e("ScanDebug", "Total publish failures: ${publish.failureCount} / ${publish.totalPackages}")
                    }
                    runCatching { safeApp.repository.clearScanPublishSummary(sessionId) }
                    runCatching { safeApp.repository.interruptScanSession(sessionId) }
                    Log.e("ScanDebug", "Worker CRASHED", error)
                    val result = Result.failure()
                    Log.d("ScanDebug", "Worker FINISHED with result: $result")
                    result
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            Log.e("ScanDebug", "Worker CRASHED", error)
            Result.failure()
        }
    }

    companion object {
        const val UNIQUE_NAME = "safe_mobile_periodic_deep_scan"
        private const val MAX_RETRIES = 2
        private const val DUPLICATE_COOLDOWN_MS = 2 * 60 * 1000L
    }
}
