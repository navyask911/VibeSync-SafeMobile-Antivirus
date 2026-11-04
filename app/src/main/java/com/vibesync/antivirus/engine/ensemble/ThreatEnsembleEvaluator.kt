package com.vibesync.antivirus.engine.ensemble

import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import java.util.UUID

/**
 * Deterministic, local-only fusion of the exact-hash, YARA and Drebin-215 signals.
 *
 * The model is advisory: a high ML score is not sufficient by itself to create a
 * threat verdict. A YARA suspicious signal is required for that escalation.
 */
object ThreatEnsembleEvaluator {
    private val exactHashSources = setOf(
        DetectionSource.HASH,
        DetectionSource.SIGNED_DATABASE,
        DetectionSource.THREAT_INTELLIGENCE_FEED
    )

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
        val yaraSuspicious = scanResult.yaraVerdict == ScanVerdict.SUSPICIOUS

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

            yaraSuspicious || (probability != null && probability >= 0.4f && probability <= 0.7f) -> {
                scanResult.copy(
                    verdict = ScanVerdict.SUSPICIOUS,
                    detectionSource = DetectionSource.ENSEMBLE,
                    confidence = probability ?: 0.0f
                )
            }

            // Preserve the pre-existing independent static-review path. It is not
            // silently erased by an empty ML/YARA signal.
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
