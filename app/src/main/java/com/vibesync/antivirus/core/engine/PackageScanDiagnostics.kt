package com.vibesync.antivirus.core.engine

import android.os.Process
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * Per-run, log-only accounting for installed-package scans.
 *
 * A package can be both failed and published: for example, hashing can fail but
 * the NOT_SCANNED result can still be persisted. failureCount counts failed stages;
 * failedPackageNames exposes the distinct package set. published counts successful
 * Room session-row callbacks.
 */
internal class PackageScanDiagnostics(
    val userId: Int = Process.myUid() / 100000
) {
    private val totalCount = AtomicInteger(0)
    private val publishedCount = AtomicInteger(0)
    private val failureCount = AtomicInteger(0)
    private val completedVerdictCount = AtomicInteger(0)
    private val pendingRetryCount = AtomicInteger(0)
    private val cacheHitCount = AtomicInteger(0)
    private val skippedReasons = ConcurrentHashMap<String, String>()
    private val queuedReasons = ConcurrentHashMap<String, String>()
    private val resumedPackages = ConcurrentHashMap.newKeySet<String>()
    private val failedPackages = ConcurrentHashMap.newKeySet<String>()

    val total: Int get() = totalCount.get()
    val published: Int get() = publishedCount.get()
    val failed: Int get() = failureCount.get()
    val completed: Int get() = completedVerdictCount.get()
    val pendingRetries: Int get() = pendingRetryCount.get()
    val cacheHits: Int get() = cacheHitCount.get()
    val failedPackageNames: Set<String> get() = failedPackages.toSet()
    val queued: Int get() = queuedReasons.size
    val resumed: Int get() = resumedPackages.size
    val skipped: Int get() = skippedReasons.size

    fun setTotal(value: Int) {
        totalCount.set(value.coerceAtLeast(0))
    }

    fun markPublished(count: Int = 1) {
        if (count > 0) publishedCount.addAndGet(count)
    }

    fun stage(packageName: String, stage: String, status: String) {
        val safeStage = stage.lowercase().replace(Regex("[^a-z0-9_]+"), "_").take(40)
        val safeStatus = status.lowercase().replace(Regex("[^a-z0-9_]+"), "_").take(40)
        Log.i("ScanDebug", "pkg_stage pkg=$packageName stage=$safeStage status=$safeStatus userId=$userId")
    }

    fun recordResult(result: ScanResult) {
        if (result.verdict == ScanVerdict.NOT_SCANNED) pendingRetryCount.incrementAndGet()
        else completedVerdictCount.incrementAndGet()
        if (result.scanSource == ScanSource.CACHE_HIT) cacheHitCount.incrementAndGet()
        val pkg = result.packageName ?: result.packageOrPath
        Log.i("ScanDebug", "pkg_complete pkg=$pkg verdict=\${result.verdict} source=\${result.scanSource} " +
            "durationMs=\${result.durationMs} apkBytes=\${result.apkSizeBytes ?: -1L} stages=\${result.analysisStages.joinToString(",")}")
    }

    fun markResumedCompleted(count: Int) {
        if (count > 0) completedVerdictCount.addAndGet(count)
    }

    fun fail(packageName: String, stage: String, error: Throwable) {
        failedPackages.add(packageName)
        failureCount.incrementAndGet()
        Log.e(
            "ScanDebug",
            "pkg_fail pkg=$packageName stage=$stage userId=$userId",
            error
        )
    }

    fun queue(packageName: String, reason: String, flags: Int) {
        val safeReason = reason.replace('\n', ' ').take(120)
        if (queuedReasons.putIfAbsent(packageName, safeReason) == null) {
            Log.i("ScanDebug", "pkg_queued pkg=$packageName reason=$safeReason flags=$flags userId=$userId")
        }
    }

    fun resume(packageName: String) {
        if (resumedPackages.add(packageName)) {
            Log.i("ScanDebug", "pkg_resume pkg=$packageName reason=already_completed_in_this_session userId=$userId")
        }
    }

    fun skip(packageName: String, reason: String) {
        val safeReason = reason.replace('\n', ' ').take(240)
        if (skippedReasons.putIfAbsent(packageName, safeReason) == null) {
            Log.i("ScanDebug", "pkg_skipped pkg=$packageName reason=$safeReason userId=$userId")
        }
    }

    fun iconNotApplicable(packageName: String) {
        // The current scanner does not load application icons at any scan stage.
        Log.d(
            "ScanDebug",
            "pkg_stage pkg=$packageName stage=icon status=not_applicable userId=$userId"
        )
    }

    fun logSummary() {
        Log.i(
            "ScanDebug",
            "scan_summary enumerated=$total queued=$queued resumed=$resumed pending=${(queued - resumed).coerceAtLeast(0)} published=$published completed=$completed pendingRetries=$pendingRetries cacheHits=$cacheHits failed=$failed skipped=$skipped userId=$userId"
        )
    }
}

/** Carries the originating per-package stage through the repository publish callback. */
internal class ScanPublishStageException(
    val stage: String,
    cause: Throwable
) : Exception("Installed-package publication failed during $stage.", cause)
