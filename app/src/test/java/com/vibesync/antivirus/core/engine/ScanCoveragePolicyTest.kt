package com.vibesync.antivirus.core.engine

import com.vibesync.antivirus.core.engine.yara.YaraXScanResult
import com.vibesync.antivirus.core.engine.yara.YaraXScanState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanCoveragePolicyTest {
    private fun clean() = ScanResult(
        packageOrPath = "com.example.app",
        displayName = "Example",
        sha256 = "a".repeat(64),
        md5 = "b".repeat(32),
        verdict = ScanVerdict.NO_MATCH,
        reasons = listOf("No exact threat signature matched."),
        durationMs = 100L,
        packageName = "com.example.app",
        analysisStages = listOf("HASH", "STATIC_ANALYSIS", "VERDICT")
    )

    @Test
    fun incompleteOptionalYaraLayerDoesNotTurnPrimaryCleanAssessmentIntoPending() {
        val result = ScanCoveragePolicy.applyYaraCoverage(
            clean(), YaraXScanState.NOT_SCANNED, "DEX component exceeded its configured bound."
        )
        assertEquals(ScanVerdict.NO_MATCH, result.verdict)
        assertTrue("YARA_INCOMPLETE" in result.analysisStages)
        assertTrue(result.reasons.any { it.contains("configured bound") })
        assertTrue(ScanCoveragePolicy.isPartial(result))
    }

    @Test
    fun disabledYaraLayerIsReportedAsPartial() {
        val result = ScanCoveragePolicy.applyYaraCoverage(
            clean(), YaraXScanState.DISABLED, "Native engine unavailable."
        )
        assertEquals(ScanVerdict.NO_MATCH, result.verdict)
        assertTrue(ScanCoveragePolicy.isPartial(result))
    }

    @Test
    fun completedLayerAndPositiveVerdictsAreNotRewritten() {
        val unchanged = ScanCoveragePolicy.applyYaraCoverage(clean(), YaraXScanState.NO_MATCH, null)
        assertEquals(clean(), unchanged)
        val threat = clean().copy(verdict = ScanVerdict.THREAT)
        val partialThreat = ScanCoveragePolicy.applyYaraCoverage(
            threat, YaraXScanState.NOT_SCANNED, "YARA coverage incomplete."
        )
        assertEquals(ScanVerdict.THREAT, partialThreat.verdict)
        assertTrue(ScanCoveragePolicy.isPartial(partialThreat))
        assertFalse(ScanCoveragePolicy.isPartial(unchanged))
    }

    @Test
    fun partialCoverageIsRetainedEvenWhenAComponentHasAMatch() {
        val match = com.vibesync.antivirus.core.engine.yara.YaraXRuleMatch(
            ruleIdentifier = "test_rule",
            namespace = "tests",
            componentName = "classes.dex",
            tags = emptyList(),
            classification = "suspicious",
            severity = "low",
            description = "fixture",
            malwareName = null,
            matchedPatterns = emptyList()
        )
        val combined = ScanCoveragePolicy.combineYara(
            listOf(YaraXScanResult(YaraXScanState.MATCHES, listOf(match))),
            listOf("second split was unreadable")
        )
        assertEquals(YaraXScanState.MATCHES, combined.state)
        val partial = ScanCoveragePolicy.applyYaraCoverage(clean(), combined.state, combined.reason)
        assertEquals(ScanVerdict.NO_MATCH, partial.verdict)
        assertTrue(ScanCoveragePolicy.isPartial(partial))
    }

    @Test
    fun splitApkCoverageRequiresAllSplitsToCompleteUnlessAThreatWasFound() {
        val cleanResult = YaraXScanResult(YaraXScanState.NO_MATCH)
        val incomplete = YaraXScanResult(YaraXScanState.NOT_SCANNED, reason = "split unreadable")
        assertEquals(
            YaraXScanState.NOT_SCANNED,
            ScanCoveragePolicy.combineYara(listOf(cleanResult, incomplete)).state
        )
        assertEquals(
            YaraXScanState.NO_MATCH,
            ScanCoveragePolicy.combineYara(listOf(cleanResult, cleanResult)).state
        )
    }
}
