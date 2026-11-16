package com.vibesync.antivirus.core.worker

import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanTimeoutPolicyTest {
    @Test
    fun installedAppScanUsesFiveMinuteProductionTimeout() {
        assertEquals(300_000L, INSTALLED_APP_SCAN_TIMEOUT_MS)
    }

    @Test
    fun timeoutCancelsBlockedInstalledAppScan() = runTest {
        var timedOut = false
        try {
            withInstalledAppScanTimeout(timeoutMillis = 50L) {
                delay(500L)
                "completed"
            }
        } catch (_: TimeoutCancellationException) {
            timedOut = true
        }
        assertTrue(timedOut)
    }

    @Test
    fun successfulScanReturnsItsValueBeforeTimeout() = runTest {
        val value = withInstalledAppScanTimeout(timeoutMillis = 500L) {
            delay(10L)
            "completed"
        }
        assertEquals("completed", value)
    }
}
