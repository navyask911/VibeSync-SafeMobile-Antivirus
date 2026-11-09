package com.vibesync.antivirus.engine.ensemble

import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class ThreatEnsembleEvaluatorTest {
    private fun result(
        verdict: ScanVerdict = ScanVerdict.NO_MATCH,
        source: DetectionSource = DetectionSource.NONE,
        yaraVerdict: ScanVerdict? = null,
        mlProbability: Float? = null
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
        mlProbability = mlProbability
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
    fun suspiciousYaraAndMlAbovePointSevenFuseToThreat() {
        val output = ThreatEnsembleEvaluator.evaluate(
            result(
                verdict = ScanVerdict.SUSPICIOUS,
                source = DetectionSource.YARA,
                yaraVerdict = ScanVerdict.SUSPICIOUS,
                mlProbability = 0.85f
            )
        )
        assertEquals(ScanVerdict.THREAT, output.verdict)
        assertEquals(DetectionSource.ENSEMBLE, output.detectionSource)
        assertEquals(0.85f, output.confidence, 0.0f)
        assertNotNull(output.threatEventId)
    }

    @Test
    fun mlProbabilityInInclusivePointFourToPointSevenBandIsSuspicious() {
        val output = ThreatEnsembleEvaluator.evaluate(result(mlProbability = 0.55f))
        assertEquals(ScanVerdict.SUSPICIOUS, output.verdict)
        assertEquals(DetectionSource.ENSEMBLE, output.detectionSource)
        assertEquals(0.55f, output.confidence, 0.0f)
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
    fun highMlProbabilityAloneDoesNotCreateThreat() {
        val output = ThreatEnsembleEvaluator.evaluate(result(mlProbability = 0.92f))
        assertEquals(ScanVerdict.NO_MATCH, output.verdict)
    }

    @Test
    fun textPayloadCandidateFilterIncludesTxtExtensionlessAndEicarNames() {
        assertEquals(true, ThreatEnsembleEvaluator.isTextPayloadCandidate("sample.txt"))
        assertEquals(true, ThreatEnsembleEvaluator.isTextPayloadCandidate("README"))
        assertEquals(true, ThreatEnsembleEvaluator.isTextPayloadCandidate("EICAR-test.data"))
        assertEquals(false, ThreatEnsembleEvaluator.isTextPayloadCandidate("sample.apk"))
        assertEquals(false, ThreatEnsembleEvaluator.isTextPayloadCandidate("photo.jpg"))
    }

    @Test
    fun exactEicarTextMarkerIsDetectedAndEscalatedAsHashThreat() {
        val marker = listOf(
            "X5O!P%@AP[4", 92.toChar().toString(), "PZX54(P^)7CC)7}",
            36.toChar().toString(), "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!",
            36.toChar().toString(), "H+H*"
        ).joinToString("")
        assertEquals(true, ThreatEnsembleEvaluator.containsEicarTextPayload(marker.toByteArray()))
        val output = ThreatEnsembleEvaluator.evaluate(result(), eicarTextMatch = true)
        assertEquals(ScanVerdict.THREAT, output.verdict)
        assertEquals(DetectionSource.HASH, output.detectionSource)
        assertEquals(1.0f, output.confidence, 0.0f)
        assertEquals("EICAR-Test-File", output.malwareName)
        assertNotNull(output.threatEventId)
    }

    @Test
    fun unreadableInputIsNeverDowngradedToNoMatch() {
        val output = ThreatEnsembleEvaluator.evaluate(result(verdict = ScanVerdict.NOT_SCANNED))
        assertEquals(ScanVerdict.NOT_SCANNED, output.verdict)
    }
}
