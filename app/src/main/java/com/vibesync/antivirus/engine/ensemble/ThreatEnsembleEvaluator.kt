package com.vibesync.antivirus.engine.ensemble

import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.RiskSeverity
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.engine.hash.HashMatcher
import java.security.MessageDigest
import java.util.UUID

/**
 * Deterministic, local-only fusion of the exact-hash, YARA and Drebin-215 signals.
 *
 * ML remains advisory. It can raise a result to SUSPICIOUS at the review floor,
 * but cannot create a THREAT verdict without qualifying YARA support.
 */
object ThreatEnsembleEvaluator {
    private const val ML_SUSPICIOUS_THRESHOLD = 0.65f
    private const val YARA_RULE_PREFIX = "YARAX_"

    /**
     * Detects the harmless EICAR test file using its pinned SHA-256 digest.
     * No test-payload bytes are embedded in application code.
     */
    fun containsEicarTestPayload(payload: ByteArray): Boolean {
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
        val sha256 = digest.joinToString("") { byte ->
            "%02x".format(byte.toInt() and 0xff)
        }
        return sha256 == HashMatcher.EICAR_SHA256
    }

    /** Applies the local SHA-256 test signature without allowing a trusted-app override. */
    fun evaluateTextPayload(scanResult: ScanResult, payload: ByteArray): ScanResult {
        if (scanResult.trustedByUser || !containsEicarTestPayload(payload)) return scanResult
        val label = HashMatcher.EICAR_MALWARE_NAME
        return scanResult.copy(
            verdict = ScanVerdict.THREAT,
            detectionSource = DetectionSource.HASH,
            confidence = 1.0f,
            riskScore = 1.0f,
            threatEventId = scanResult.threatEventId ?: UUID.randomUUID().toString(),
            malwareName = label,
            reasons = (scanResult.reasons + label).distinct()
        )
    }

    private val exactHashSources = setOf(
        DetectionSource.HASH,
        DetectionSource.SIGNED_DATABASE,
        DetectionSource.THREAT_INTELLIGENCE_FEED
    )

    private fun hasQualifyingYaraSignal(scanResult: ScanResult): Boolean {
        val findings = scanResult.riskReport?.findings.orEmpty()
            .filter { it.ruleId.startsWith(YARA_RULE_PREFIX) }
        val lowSeverityCount = findings.count { it.severity == RiskSeverity.LOW }
        val hasMediumOrHighSeverity = findings.any { it.severity != RiskSeverity.LOW }
        // A single low-severity rule is retained in the report as evidence,
        // but cannot independently influence the fused verdict.
        return hasMediumOrHighSeverity || lowSeverityCount >= 2
    }

    fun evaluate(scanResult: ScanResult): ScanResult {
        if (scanResult.detectionSource == DetectionSource.HASH &&
            scanResult.verdict == ScanVerdict.THREAT
        ) {
            return scanResult.copy(confidence = 1.0f)
        }

        if (scanResult.detectionSource == DetectionSource.YARA &&
            scanResult.verdict == ScanVerdict.THREAT
        ) {
            return scanResult.copy(confidence = 0.9f)
        }

        // Signed-database and explicitly enabled feed hits are exact digest matches
        // too. Preserve their source labels and definitive verdicts.
        if (scanResult.detectionSource in exactHashSources &&
            scanResult.verdict == ScanVerdict.THREAT
        ) {
            return scanResult.copy(confidence = 1.0f)
        }

        // Never turn an inaccessible/partial scan or a user-approved app into clean.
        if (scanResult.verdict == ScanVerdict.NOT_SCANNED || scanResult.trustedByUser) {
            return scanResult
        }

        val probability = scanResult.mlProbability
            ?.takeIf { it.isFinite() && it in 0.0f..1.0f }
        val yaraSuspicious = hasQualifyingYaraSignal(scanResult)

        return when {
            yaraSuspicious && probability != null && probability > 0.7f -> {
                scanResult.copy(
                    verdict = ScanVerdict.THREAT,
                    detectionSource = DetectionSource.ENSEMBLE,
                    confidence = probability,
                    riskScore = 1.0f,
                    threatEventId = scanResult.threatEventId ?: UUID.randomUUID().toString()
                )
            }

            yaraSuspicious || (probability != null && probability >= ML_SUSPICIOUS_THRESHOLD) -> {
                scanResult.copy(
                    verdict = ScanVerdict.SUSPICIOUS,
                    detectionSource = DetectionSource.ENSEMBLE,
                    confidence = probability ?: 0.0f
                )
            }

            // Preserve the pre-existing independent static-review path.
            scanResult.verdict == ScanVerdict.SUSPICIOUS &&
                scanResult.detectionSource == DetectionSource.HEURISTIC -> scanResult

            else -> scanResult.copy(
                verdict = ScanVerdict.NO_MATCH,
                detectionSource = DetectionSource.NONE,
                confidence = 0.0f
            )
        }
    }
}
