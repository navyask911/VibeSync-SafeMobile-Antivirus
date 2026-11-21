package com.vibesync.antivirus.core.engine

/** Only completed verdicts are stable enough to reuse across installed-app scan sessions. */
internal object AppScanCachePolicy {
    fun canReuse(verdict: ScanVerdict?): Boolean =
        verdict != null && verdict != ScanVerdict.NOT_SCANNED

    fun shouldPersist(verdict: ScanVerdict): Boolean =
        verdict != ScanVerdict.NOT_SCANNED
}
