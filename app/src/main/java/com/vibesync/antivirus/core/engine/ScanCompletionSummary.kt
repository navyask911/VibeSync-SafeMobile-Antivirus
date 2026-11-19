package com.vibesync.antivirus.core.engine

/** Counts and aggregate metrics only; package names, paths and hashes stay in item rows. */
data class ScanCompletionSummary(
    val appCount: Int,
    val fileCount: Int,
    val threats: Int,
    val review: Int,
    val unreadable: Int,
    val completedAt: Long,
    val signedDefinitionsUsed: Boolean = false,
    val skippedFiles: Int = 0,
    val startedAt: Long = completedAt,
    val elapsedMs: Long = 0L,
    val totalApkBytes: Long = 0L,
    val scannedApkBytes: Long = 0L,
    val completedAppCount: Int = appCount,
    val appsPerSecond: Double = 0.0,
    val mbPerSecond: Double = 0.0,
    val pendingRetries: Int = unreadable,
    val cachedAppCount: Int = 0,
    val freshAppCount: Int = 0,
    val verifiedGoogleAppCount: Int = 0,
    val enumeratedPackages: Int = 0,
    val queuedPackages: Int = 0,
    val excludedPackages: Int = 0
) {
    companion object {
        fun from(
            results: List<ScanResult>,
            processed: Int,
            now: Long,
            skippedFiles: Int = 0,
            startedAt: Long = now,
            elapsedMsOverride: Long? = null,
            enumeratedPackages: Int = 0,
            queuedPackages: Int = 0,
            excludedPackages: Int = 0
        ): ScanCompletionSummary {
            val appResults = results.filter { it.packageName != null }
            val apps = appResults.size
            val total = maxOf(processed, results.size)
            val freshApps = appResults.count { it.scanSource == ScanSource.FRESH }
            val cachedApps = appResults.count { it.scanSource == ScanSource.CACHE_HIT }
            val verifiedGoogleApps = appResults.count { it.scanSource == ScanSource.GOOGLE_VERIFIED }
            val completedApps = appResults.count { it.verdict != ScanVerdict.NOT_SCANNED }
            val pending = appResults.count { it.verdict == ScanVerdict.NOT_SCANNED }
            val totalBytes = appResults.fold(0L) { accumulated, result ->
                val next = (result.apkSizeBytes ?: 0L).coerceAtLeast(0L)
                if (Long.MAX_VALUE - accumulated < next) Long.MAX_VALUE else accumulated + next
            }
            // Count bytes only where the Hash stage confirms that the APK was read.
            // A later YARA/ML retry can remain pending while its hashed bytes were processed.
            val scannedBytes = appResults.asSequence()
                .filter { it.scanSource == ScanSource.FRESH && "HASH" in it.analysisStages }
                .fold(0L) { accumulated, result ->
                    val next = (result.apkSizeBytes ?: 0L).coerceAtLeast(0L)
                    if (Long.MAX_VALUE - accumulated < next) Long.MAX_VALUE else accumulated + next
                }
            val elapsed = (elapsedMsOverride ?: (now - startedAt)).coerceAtLeast(0L)
            val seconds = elapsed / 1_000.0
            val appsPerSecond = if (seconds > 0.0) completedApps / seconds else 0.0
            val mbPerSecond = if (seconds > 0.0) scannedBytes / (1024.0 * 1024.0) / seconds else 0.0
            return ScanCompletionSummary(
                appCount = apps,
                fileCount = (total - apps).coerceAtLeast(0),
                threats = results.count { it.verdict == ScanVerdict.THREAT },
                review = results.count { it.verdict == ScanVerdict.SUSPICIOUS },
                unreadable = results.count { it.verdict == ScanVerdict.NOT_SCANNED },
                completedAt = now,
                skippedFiles = skippedFiles.coerceAtLeast(0),
                startedAt = startedAt,
                elapsedMs = elapsed,
                totalApkBytes = totalBytes,
                scannedApkBytes = scannedBytes,
                completedAppCount = completedApps,
                appsPerSecond = appsPerSecond,
                mbPerSecond = mbPerSecond,
                pendingRetries = pending,
                cachedAppCount = cachedApps,
                freshAppCount = freshApps,
                verifiedGoogleAppCount = verifiedGoogleApps,
                enumeratedPackages = enumeratedPackages.coerceAtLeast(0),
                queuedPackages = queuedPackages.coerceAtLeast(0),
                excludedPackages = excludedPackages.coerceAtLeast(0)
            )
        }
    }
}
