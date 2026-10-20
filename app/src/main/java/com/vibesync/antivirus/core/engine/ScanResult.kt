package com.vibesync.antivirus.core.engine
enum class ScanVerdict { THREAT, SUSPICIOUS, NO_MATCH, NOT_SCANNED }
data class ScanResult(
 val packageOrPath: String,
 val displayName: String,
 val sha256: String?,
 val md5: String?,
 val verdict: ScanVerdict,
 val reasons: List<String>,
 val durationMs: Long
)
