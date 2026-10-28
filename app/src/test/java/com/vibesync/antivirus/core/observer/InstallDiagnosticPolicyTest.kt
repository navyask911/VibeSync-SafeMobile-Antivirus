package com.vibesync.antivirus.core.observer

import org.junit.Assert.*
import org.junit.Test

class InstallDiagnosticPolicyTest {
    @Test fun retriesDoNotRestartAnAlarmButANewInstallStillCan() {
        val gate = InstallAlarmGate()
        assertTrue(gate.claim("first-install"))
        assertFalse(gate.claim("first-install"))
        assertTrue(gate.claim("second-install"))
        assertFalse(gate.claim("second-install"))
    }

    @Test fun releaseMarkerIsRestrictedToTheReservedFixtureIdentity() {
        assertTrue(InstallDiagnosticPolicy.shouldTest("com.safemobile.sirentest", false))
        assertFalse(InstallDiagnosticPolicy.shouldTest("org.example.sirentest", false))
        assertFalse(InstallDiagnosticPolicy.shouldTest("com.safemobile.sirentest.attacker", false))
        assertFalse(InstallDiagnosticPolicy.shouldTest("com.whatsapp", true))
    }

    @Test fun debugMarkerNormalizesTheHyphenatedFileLabel() {
        assertTrue(InstallDiagnosticPolicy.shouldTest("org.example.Siren_Test", true))
        assertTrue(InstallDiagnosticPolicy.shouldTest("org.example.Siren-Test", true))
    }
}
