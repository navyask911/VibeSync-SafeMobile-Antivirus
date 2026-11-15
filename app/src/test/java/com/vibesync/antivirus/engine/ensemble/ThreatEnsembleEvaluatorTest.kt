package com.vibesync.antivirus.engine.ensemble

import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.RiskFinding
import com.vibesync.antivirus.core.engine.RiskReport
import com.vibesync.antivirus.core.engine.RiskSeverity
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class ThreatEnsembleEvaluatorTest {
    private fun lowYaraFinding(index: Int) = RiskFinding(
        ruleId = "YARAX_LOW_$index",
        severity = RiskSeverity.LOW,
        evidence = "Low-severity YARA fixture $index",
        confidence = 35
    )

    private fun result(
        verdict: ScanVerdict = ScanVerdict.NO_MATCH,
        source: DetectionSource = DetectionSource.NONE,
        yaraVerdict: ScanVerdict? = null,
        mlProbability: Float? = null,
        yaraFindings: List<RiskFinding> = emptyList()
    ) = ScanResult(
        packageOrPath = "sample.apk",
        displayName = "Sample",
        sha256 = "a".repeat(64),
        md5 = "b".repeat(32),
        verdict = verdict,
        reasons = emptyList(),
        durationMs = 1L,
        detectionSource = source,
        yaraVerdict = yaraVerdict,
        mlProbability = mlProbability,
        riskReport = yaraFindings.takeIf { it.isNotEmpty() }
            ?.let { RiskReport(findings = it, riskScore = 0) }
    )

    @Test
    fun hashMatchIsThreatWithFullConfidence() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(verdict = ScanVerdict.THREAT, source = DetectionSource.HASH)
        )
        assertEquals(ScanVerdict.THREAT, output.verdict)
        assertEquals(DetectionSource.HASH, output.detectionSource)
        assertEquals(1.0f, output.confidence, 0.0f)
    }

    @Test
    fun yaraMatchIsThreatWithNinetyPercentConfidence() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(verdict = ScanVerdict.THREAT, source = DetectionSource.YARA)
        )
        assertEquals(ScanVerdict.THREAT, output.verdict)
        assertEquals(DetectionSource.YARA, output.detectionSource)
        assertEquals(0.9f, output.confidence, 0.0f)
    }

    @Test
    fun twoLowSeverityYaraMatchesAndHighMlProbabilityFuseToThreat() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(
                verdict = ScanVerdict.SUSPICIOUS,
                source = DetectionSource.YARA,
                yaraVerdict = ScanVerdict.SUSPICIOUS,
                mlProbability = 0.85f,
                yaraFindings = listOf(lowYaraFinding(1), lowYaraFinding(2))
            )
        )
        assertEquals(ScanVerdict.THREAT, output.verdict)
        assertEquals(DetectionSource.ENSEMBLE, output.detectionSource)
        assertEquals(0.85f, output.confidence, 0.0f)
        assertNotNull(output.threatEventId)
    }

    @Test
    fun oneLowSeverityYaraMatchIsLoggedButDoesNotFlagSuspicious() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(
                yaraVerdict = ScanVerdict.SUSPICIOUS,
                mlProbability = 0.2f,
                yaraFindings = listOf(lowYaraFinding(1))
            )
        )
        assertEquals(ScanVerdict.NO_MATCH, output.verdict)
        assertEquals(DetectionSource.NONE, output.detectionSource)
        assertEquals(1, output.riskReport?.findings?.size)
    }

    @Test
    fun twoLowSeverityYaraMatchesAreSuspiciousWithoutMlSupport() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(
                yaraVerdict = ScanVerdict.SUSPICIOUS,
                yaraFindings = listOf(lowYaraFinding(1), lowYaraFinding(2))
            )
        )
        assertEquals(ScanVerdict.SUSPICIOUS, output.verdict)
        assertEquals(DetectionSource.ENSEMBLE, output.detectionSource)
    }

    @Test
    fun mediumSeverityYaraMatchCanStillRaiseSuspicious() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(
                yaraVerdict = ScanVerdict.SUSPICIOUS,
                yaraFindings = listOf(
                    RiskFinding("YARAX_MEDIUM_1", RiskSeverity.MEDIUM, "Medium fixture", 55)
                )
            )
        )
        assertEquals(ScanVerdict.SUSPICIOUS, output.verdict)
    }

    @Test
    fun mlProbabilityBelowPointSixFiveIsNoMatch() {
        val output = ThreatEnsembleEvaluator.evaluate(result(mlProbability = 0.649f))
        assertEquals(ScanVerdict.NO_MATCH, output.verdict)
        assertEquals(DetectionSource.NONE, output.detectionSource)
    }

    @Test
    fun mlProbabilityAtPointSixFiveIsSuspicious() {
        val output = ThreatEnsembleEvaluator.evaluate(result(mlProbability = 0.65f))
        assertEquals(ScanVerdict.SUSPICIOUS, output.verdict)
        assertEquals(DetectionSource.ENSEMBLE, output.detectionSource)
        assertEquals(0.65f, output.confidence, 0.0f)
    }

    @Test
    fun mlProbabilityAloneCanBeSuspiciousButNeverThreat() {
        val output = ThreatEnsembleEvaluator.evaluate(result(mlProbability = 0.92f))
        assertEquals(ScanVerdict.SUSPICIOUS, output.verdict)
        assertEquals(DetectionSource.ENSEMBLE, output.detectionSource)
        assertNull(output.threatEventId)
    }

    @Test
    fun allCleanSignalsProduceNoMatch() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(
                verdict = ScanVerdict.NO_MATCH,
                source = DetectionSource.NONE,
                yaraVerdict = ScanVerdict.NO_MATCH,
                mlProbability = 0.2f
            )
        )
        assertEquals(ScanVerdict.NO_MATCH, output.verdict)
        assertEquals(DetectionSource.NONE, output.detectionSource)
        assertEquals(0.0f, output.confidence, 0.0f)
    }

    @Test
    fun ordinaryTextPayloadDoesNotMatchPinnedEicarSha256() {
        val output = ThreatEnsembleEvaluator.evaluateTextPayload(
            result().copy(packageOrPath = "sample.txt", displayName = "sample.txt"),
            "ordinary text content".toByteArray(Charsets.US_ASCII)
        )
        assertEquals(ScanVerdict.NO_MATCH, output.verdict)
    }

    @Test
    fun eicarFilenameWithoutPayloadDoesNotTriggerDetection() {
        val output = ThreatEnsembleEvaluator.evaluateTextPayload(
            result().copy(packageOrPath = "eicar.txt", displayName = "eicar.txt"),
            "This is an ordinary text file.".toByteArray(Charsets.US_ASCII)
        )
        assertEquals(ScanVerdict.NO_MATCH, output.verdict)
    }

    @Test
    fun unreadableInputIsNeverDowngradedToNoMatch() {
        val output = ThreatEnsembleEvaluator.evaluate(result(verdict = ScanVerdict.NOT_SCANNED))
        assertEquals(ScanVerdict.NOT_SCANNED, output.verdict)
    }
}
