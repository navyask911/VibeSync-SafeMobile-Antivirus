package com.vibesync.antivirus.core.worker

/** A scan must persist at least one item and must not silently lose any published item. */
internal object ScanPublishPolicy {
    fun shouldFail(scannedItems: Int, publishFailures: Int): Boolean =
        scannedItems <= 0 || publishFailures > 0

    /** Retry incomplete verdicts for a bounded number of worker attempts, then fail visibly. */
    fun shouldRetry(pendingRetries: Int, runAttemptCount: Int, maxRetries: Int = 2): Boolean =
        pendingRetries > 0 && runAttemptCount < maxRetries
}
