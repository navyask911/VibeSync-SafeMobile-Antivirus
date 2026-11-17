package com.vibesync.antivirus.core.worker

import kotlinx.coroutines.sync.Mutex

/**
 * Serializes foreground-service and WorkManager scans because they share the
 * Room session/checkpoint tables and the installed-app scanner.
 */
object ScanExecutionCoordinator {
    val mutex = Mutex()
}
