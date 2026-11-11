package com.vibesync.antivirus.core.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class IntegrityCheckerTest {
    private class FakeProbe(
        private val paths: Set<String> = emptySet(), private val packages: Set<String> = emptySet(),
        private val properties: Map<String, String> = emptyMap(), private val selinux: Boolean? = true,
        private val debugger: Boolean = false, private val emulator: Boolean = false
    ) : IntegrityProbe {
        override fun pathExists(path: String) = path in paths
        override fun packageInstalled(packageName: String) = packageName in packages
        override fun systemProperty(name: String) = properties[name]
        override fun selinuxEnforced() = selinux
        override fun debuggerAttached() = debugger
        override fun emulatorLikely() = emulator
    }
    @Test fun cleanSignalsReturnBaselineMultiplier() {
        val r = IntegrityChecker(FakeProbe()).check()
        assertFalse(r.isUntrusted); assertTrue(r.reasons.isEmpty()); assertEquals(1.0f, r.riskMultiplier, 0.0f)
    }
    @Test fun rootPathRaisesMultiplier() {
        val r = IntegrityChecker(FakeProbe(paths = setOf("/system/bin/su"))).check()
        assertTrue(r.isUntrusted); assertTrue(r.reasons.any { it.contains("Root-related") }); assertTrue(r.riskMultiplier > 1.0f)
    }
    @Test fun buildPropertySelinuxDebuggerAndEmulatorChecksAreIndependent() {
        val r = IntegrityChecker(FakeProbe(properties = mapOf("ro.debuggable" to "1", "ro.secure" to "0", "ro.build.tags" to "test-keys"),
            selinux = false, debugger = true, emulator = true)).check()
        assertTrue(r.reasons.any { it.contains("Build tags") }); assertTrue(r.reasons.any { it.contains("debuggable") })
        assertTrue(r.reasons.any { it.contains("SELinux") }); assertTrue(r.reasons.any { it.contains("debugger") })
        assertTrue(r.reasons.any { it.contains("emulator") }); assertTrue(r.riskMultiplier <= 1.5f)
    }
    @Test fun unknownSelinuxStateIsNotMarkedAsFailure() {
        val r = IntegrityChecker(FakeProbe(selinux = null)).check()
        assertFalse(r.reasons.any { it.contains("SELinux") })
    }
}
