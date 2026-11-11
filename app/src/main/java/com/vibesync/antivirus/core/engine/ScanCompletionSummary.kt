package com.vibesync.antivirus.core.engine

/** Counts only; no package names, paths or hashes are saved in summary preferences. */
data class ScanCompletionSummary(
    val appCount: Int, val fileCount: Int, val threats: Int, val review: Int, val unreadable: Int, val completedAt: Long, val signedDefinitionsUsed: Boolean = false
) {
    companion object {
        fun from(results: List<ScanResult>, processed: Int, now: Long): ScanCompletionSummary {
            val apps = results.count { it.packageName != null }
            val total = maxOf(processed, results.size)
            return ScanCompletionSummary(apps, (total - apps).coerceAtLeast(0),
                results.count { it.verdict == ScanVerdict.THREAT }, results.count { it.verdict == ScanVerdict.SUSPICIOUS },
                results.count { it.verdict == ScanVerdict.NOT_SCANNED }, now)
        }
    }
}
