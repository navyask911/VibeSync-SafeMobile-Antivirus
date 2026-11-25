package com.vibesync.antivirus.core.engine

/** Only completed, full-coverage verdicts are stable enough to reuse across app-scan sessions. */
internal object AppScanCachePolicy {
    fun canReuse(verdict: ScanVerdict?): Boolean =
        verdict != null && verdict != ScanVerdict.NOT_SCANNED

    fun shouldPersist(verdict: ScanVerdict): Boolean =
        verdict != ScanVerdict.NOT_SCANNED

    fun shouldPersist(result: ScanResult): Boolean =
        result.verdict != ScanVerdict.NOT_SCANNED && !ScanCoveragePolicy.isPartial(result)
}
