package com.vibesync.antivirus.core.locale

import android.content.Context
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.RiskFinding
import com.vibesync.antivirus.core.engine.RiskReport
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability

/** Internal engine identifiers and diagnostic prose are never used as UI labels. */
object SecurityText {
    fun severity(value: String): Int = when (value.lowercase(java.util.Locale.ROOT)) {
        "test" -> R.string.severity_test
        "low" -> R.string.severity_low
        "medium" -> R.string.severity_medium
        "high" -> R.string.severity_high
        "critical" -> R.string.severity_critical
        else -> R.string.severity_unknown
    }
    fun verdict(value: String): Int = when (value) {
        "THREAT" -> R.string.verdict_threat
        "SUSPICIOUS" -> R.string.verdict_suspicious
        "NO_MATCH" -> R.string.verdict_no_match
        else -> R.string.verdict_not_scanned
    }

    val coverage = mapOf(
        "local-hash-definitions" to (R.string.coverage_local_title to R.string.coverage_local_body),
        "signed-multi-hash-database" to (R.string.coverage_signed_title to R.string.coverage_signed_body),
        "deep-static-risk-report" to (R.string.coverage_static_title to R.string.coverage_static_body),
        "permission-and-manifest" to (R.string.coverage_permissions_title to R.string.coverage_permissions_body),
        "root-hook-device-integrity" to (R.string.coverage_integrity_title to R.string.coverage_integrity_body),
        "bloom-hash-index" to (R.string.coverage_bloom_title to R.string.coverage_bloom_body),
        "yara-dex-and-assets" to (R.string.coverage_rules_title to R.string.coverage_rules_body),
        "tflite-permission-model" to (R.string.coverage_model_title to R.string.coverage_model_body),
        "offline-signer-attestation" to (R.string.coverage_signer_title to R.string.coverage_signer_body),
        "signed-feed-manifest" to (R.string.coverage_feed_title to R.string.coverage_feed_body)
    )

    fun hashStatus(capability: HashDatabaseCapability): UiText = when {
        capability.enabled -> UiText(R.string.hash_status_active)
        capability.reason.contains("integrity", true) || capability.reason.contains("format", true) -> UiText(R.string.hash_status_invalid)
        capability.reason.contains("activation", true) -> UiText(R.string.hash_status_activation)
        capability.reason.contains("key", true) -> UiText(R.string.hash_status_key)
        else -> UiText(R.string.hash_status_missing)
    }

    fun findingResource(id: String): Int = when {
        id.startsWith("EXPORTED_") -> R.string.finding_exported
        id.startsWith("PACKER_NAME_") -> R.string.finding_packer
        id.startsWith("YARA_") -> R.string.finding_rules
        else -> when (id) {
            "DEVICE_ADMIN_RECEIVER_DECLARED" -> R.string.finding_admin
            "ACCESSIBILITY_SERVICE_DECLARED" -> R.string.finding_accessibility
            "OVERLAY_PERMISSION_REQUESTED" -> R.string.finding_overlay
            "ACCESSIBILITY_COMBINED_WITH_SENSITIVE_CAPABILITY" -> R.string.finding_combined
            "SMS_AND_CALL_LOG_COMBINATION" -> R.string.finding_sms_calls
            "SMS_WITH_INTERNET" -> R.string.finding_sms_network
            "DEBUG_CERTIFICATE" -> R.string.debug_certificate
            "SIGNER_CERTIFICATE_UNAVAILABLE" -> R.string.finding_signer
            "APK_ARCHIVE_UNREADABLE" -> R.string.finding_archive
            "DEX_HEADER_ANOMALY" -> R.string.finding_dex_header
            "DEX_HEADER_TRUNCATED" -> R.string.finding_dex_short
            "DEX_HIGH_ENTROPY_SAMPLE" -> R.string.finding_entropy
            "REQUESTED_PERMISSION_API_REFERENCE_MISMATCH" -> R.string.finding_api
            else -> R.string.finding_other
        }
    }

    fun finding(finding: RiskFinding): UiText {
        val summary = UiText(R.string.finding_confidence, listOf(UiText(findingResource(finding.ruleId)), finding.confidence))
        return if (finding.details.isEmpty()) summary
        else UiText(R.string.format_finding_detail, listOf(summary, finding.details.joinToString(", ")))
    }

    private val simpleReasons = listOf(
        R.string.no_match_detail, R.string.hash_allowlisted, R.string.apk_unreadable,
        R.string.file_not_readable, R.string.file_could_not_read, R.string.package_metadata_missing,
        R.string.file_stream_failed, R.string.debug_certificate, R.string.trusted_app_explanation,
        R.string.risk_boot, R.string.risk_overlay, R.string.risk_install, R.string.risk_accessibility,
        R.string.risk_cluster, R.string.risk_review, R.string.risk_sms_internet,
        R.string.risk_sms_accessibility, R.string.risk_accessibility_overlay, R.string.risk_boot_sms_internet
    )

    fun reasons(context: Context, raw: List<String>, report: RiskReport? = null): List<UiText> = raw.map { reason ->
        val match = report?.findings?.firstOrNull { reason.startsWith("[${it.ruleId}]") }
        if (match != null) return@map finding(match)
        simpleReasons.firstOrNull { context.getString(it) == reason }?.let { return@map UiText(it) }
        val count = Regex("\\((\\d+)\\)").find(reason)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        when {
            reason.startsWith("Root-related filesystem") -> UiText(R.plurals.l10n_root_indicators, listOf(count), count)
            reason.startsWith("Xposed/LSPosed/Riru") -> UiText(R.plurals.l10n_hook_indicators, listOf(count), count)
            reason.startsWith("Root/hook manager visible: ") -> UiText(R.string.integrity_manager, listOf(reason.substringAfter(": ")))
            reason.startsWith("Build tags contain") -> UiText(R.string.integrity_test_keys)
            reason.startsWith("Build properties indicate") -> UiText(R.string.integrity_debug_build)
            reason.startsWith("SELinux is not enforcing") -> UiText(R.string.integrity_selinux)
            reason.startsWith("A debugger is attached") -> UiText(R.string.integrity_debugger)
            reason.startsWith("Build properties resemble") -> UiText(R.string.integrity_emulator)
            else -> UiText(R.string.finding_other)
        }
    }

    fun incidentStatus(status: String): Int = when {
        status.contains("MALWARE_HASH_MATCH") -> R.string.audit_scan_threat
        status.contains("RISK_REVIEW") -> R.string.audit_scan_review
        status.contains("SCAN_UNAVAILABLE") -> R.string.audit_scan_unavailable
        status.contains("SCAN_COMPLETE") -> R.string.audit_scan_complete
        status.contains("TRUSTED") -> R.string.trusted_app_explanation
        else -> R.string.audit_scan_pending
    }

    fun incidentAction(action: String): Int = when {
        action.contains("UNINSTALL_SUCCESS") -> R.string.audit_uninstall_success
        action.contains("UNINSTALL_FAILED") || action.contains("UNINSTALL_FAILURE") -> R.string.audit_uninstall_failed
        action.contains("UNINSTALL") -> R.string.audit_uninstall_requested
        else -> R.string.audit_source_recorded
    }
}
