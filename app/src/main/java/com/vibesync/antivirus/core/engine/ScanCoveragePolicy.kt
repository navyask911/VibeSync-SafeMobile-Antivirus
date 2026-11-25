package com.vibesync.antivirus.core.engine

import com.vibesync.antivirus.core.engine.yara.YaraXScanResult
import com.vibesync.antivirus.core.engine.yara.YaraXScanState

/** A completed primary assessment is not discarded when an optional layer is incomplete. */
internal object ScanCoveragePolicy {
    fun applyYaraCoverage(
        result: ScanResult,
        state: YaraXScanState?,
        reason: String?
    ): ScanResult {
        val incomplete = state == YaraXScanState.DISABLED ||
            state == YaraXScanState.NOT_SCANNED || !reason.isNullOrBlank()
        if (!incomplete) return result
        return applyPartialCoverage(
            result,
            stage = "YARA_INCOMPLETE",
            reason = "YARA-X coverage incomplete: ${reason?.takeIf { it.isNotBlank() } ?: "engine did not complete"}."
        )
    }

    fun applyPartialCoverage(result: ScanResult, stage: String, reason: String): ScanResult {
        return result.copy(
            reasons = (result.reasons + reason.take(500)).distinct(),
            analysisStages = (result.analysisStages + stage).distinct()
        )
    }

    fun isPartial(result: ScanResult): Boolean =
        result.analysisStages.any { it in PARTIAL_STAGES }

    /** Returns the scanner's reason so a partial clean verdict is never shown without context. */
    fun partialReason(result: ScanResult): String? {
        if (!isPartial(result)) return null
        return result.reasons.lastOrNull { reason ->
            listOf("incomplete", "unreadable", "unavailable", "exceeded", "failed", "limit")
                .any { marker -> reason.contains(marker, ignoreCase = true) }
        }?.take(500) ?: "One or more optional inspection stages did not complete."
    }

    fun combineYara(
        results: List<YaraXScanResult>,
        incompleteReasons: List<String> = emptyList()
    ): YaraXScanResult {
        val matches = results.flatMap { it.matches }
            .distinctBy { it.namespace + ":" + it.ruleIdentifier + ":" + it.componentName }
        val reasons = (incompleteReasons + results.mapNotNull { it.reason })
            .filter { it.isNotBlank() }.distinct()
        val complete = results.isNotEmpty() && results.all { it.isComplete } && reasons.isEmpty()
        val state = when {
            matches.isNotEmpty() -> YaraXScanState.MATCHES
            complete -> YaraXScanState.NO_MATCH
            results.any { it.state == YaraXScanState.DISABLED } -> YaraXScanState.DISABLED
            else -> YaraXScanState.NOT_SCANNED
        }
        val reason = reasons.joinToString(" ").take(500).takeIf { it.isNotBlank() }
        return YaraXScanResult(state, matches, reason)
    }

    private val PARTIAL_STAGES = setOf(
        "YARA_INCOMPLETE",
        "SPLIT_INCOMPLETE",
        "ARCHIVE_INCOMPLETE"
    )
}
