package com.vibesync.antivirus.core.engine
enum class ScanVerdict { THREAT, SUSPICIOUS, NO_MATCH, NOT_SCANNED }
data class ScanResult(
 val packageOrPath: String,
 val displayName: String,
 val sha256: String?,
 val md5: String?,
 val verdict: ScanVerdict,
 val reasons: List<String>,
 val durationMs: Long,
 val packageName: String? = null,
 val sourceUri: String? = null,
 val sourceLocalPath: String? = null,
 /** UUIDv4 shared by all assessments that belong to a single scan operation. */
 val scanSessionId: String? = null,
 /** Separate UUIDv4 identifier for each confirmed local signature match. */
 val threatEventId: String? = null,
 /** Normalized local triage score; heuristics alone do not establish malware. */
 val riskScore: Float = 0f,
 /** SHA-1 digest computed in the same streaming pass when available. */
 val sha1: String? = null,
 /** Structured, local-only static analysis findings; not persisted as an unencrypted database object. */
 val riskReport: RiskReport? = null,
 /** User override; no detection engine was executed. */
 val trustedByUser: Boolean = false,
 /** Resource-backed copy is resolved against the current Activity locale. */
 val reasonTexts: List<com.vibesync.antivirus.core.locale.UiText> = emptyList()
)
