package com.vibesync.antivirus.core.observer

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ManualThreatAlertPolicyTest {
    @Test
    fun manualConfirmedThreatAlwaysRequestsSiren() {
        assertTrue(ManualThreatAlertPolicy.shouldAlert(
            isManualScan = true,
            hasConfirmedThreat = true
        ))
    }

    @Test
    fun cleanOrSuspiciousManualScansDoNotRequestSiren() {
        assertFalse(ManualThreatAlertPolicy.shouldAlert(
            isManualScan = true,
            hasConfirmedThreat = false
        ))
    }

    @Test
    fun automaticThreatScanDoesNotUseTheForegroundManualSirenPath() {
        assertFalse(ManualThreatAlertPolicy.shouldAlert(
            isManualScan = false,
            hasConfirmedThreat = true
        ))
    }
}
