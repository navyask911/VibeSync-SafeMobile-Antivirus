package com.vibesync.antivirus.core.engine

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
    private val skippedReasons = ConcurrentHashMap<String, String>()
    private val failedPackages = ConcurrentHashMap.newKeySet<String>()

    val total: Int get() = totalCount.get()
    val published: Int get() = publishedCount.get()
    val failed: Int get() = failureCount.get()
    val failedPackageNames: Set<String> get() = failedPackages.toSet()
    val skipped: Int get() = skippedReasons.size

    fun setTotal(value: Int) {
        totalCount.set(value.coerceAtLeast(0))
    }

    fun markPublished(count: Int = 1) {
        if (count > 0) publishedCount.addAndGet(count)
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

    fun skip(packageName: String, reason: String) {
        skippedReasons.putIfAbsent(packageName, reason.replace('\n', ' ').take(240))
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
            "scan_summary total=$total published=$published failed=$failed skipped=$skipped"
        )
        skippedReasons.toSortedMap().forEach { (packageName, reason) ->
            Log.i(
                "ScanDebug",
                "pkg_skipped pkg=$packageName reason=$reason userId=$userId"
            )
        }
    }
}

/** Carries the originating per-package stage through the repository publish callback. */
internal class ScanPublishStageException(
    val stage: String,
    cause: Throwable
) : Exception("Installed-package publication failed during $stage.", cause)
