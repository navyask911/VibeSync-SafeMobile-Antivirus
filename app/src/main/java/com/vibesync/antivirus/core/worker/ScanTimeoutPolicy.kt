package com.vibesync.antivirus.core.worker

import kotlinx.coroutines.withTimeout

internal const val INSTALLED_APP_SCAN_TIMEOUT_MS = 300_000L

/**
 * Bounds PackageManager/Room-backed installed-app scans so a blocked package or
 * persistence callback cannot leave the foreground service and UI active forever.
 */
internal suspend fun <T> withInstalledAppScanTimeout(
    timeoutMillis: Long = INSTALLED_APP_SCAN_TIMEOUT_MS,
    block: suspend () -> T
): T = withTimeout(timeoutMillis) { block() }
