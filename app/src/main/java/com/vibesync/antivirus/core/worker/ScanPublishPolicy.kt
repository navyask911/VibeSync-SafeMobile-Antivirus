package com.vibesync.antivirus.core.worker

/** A scan must persist at least one item and must not silently lose any published item. */
internal object ScanPublishPolicy {
 fun shouldFail(scannedItems: Int, publishFailures: Int): Boolean =
  scannedItems <= 0 || publishFailures > 0
}
