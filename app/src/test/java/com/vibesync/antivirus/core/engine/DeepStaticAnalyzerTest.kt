package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class DeepStaticAnalyzerTest {
    @Test fun combinesSensitivePermissionsExportedReceiverAndDebugSigningAsAdvisoryFindings() {
        val report = DeepStaticAnalyzer.analyzeObservations(
            requestedPermissions = setOf(
                "android.permission.READ_SMS", "android.permission.READ_CALL_LOG",
                "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"
            ),
            hasAccessibilityService = true,
            deviceAdminReceivers = listOf("AdminReceiver"),
            components = listOf(ComponentExposure("receiver", "UnprotectedReceiver", exported = true)),
            debugCertificate = true,
            signerMaterialAvailable = true,
            entryNames = setOf("lib/arm64-v8a/libjiagu.so"),
            dexSamples = listOf(DeepStaticDexSample("classes.dex", ByteArray(128))),
            archiveIssues = emptyList()
        )
        val ids = report.findings.map { it.ruleId }.toSet()
        assertTrue(ids.contains("SMS_AND_CALL_LOG_COMBINATION"))
        assertTrue(ids.contains("ACCESSIBILITY_COMBINED_WITH_SENSITIVE_CAPABILITY"))
        assertTrue(ids.contains("EXPORTED_RECEIVER_UNPROTECTED"))
        assertTrue(ids.contains("DEBUG_CERTIFICATE"))
        assertTrue(ids.contains("DEVICE_ADMIN_RECEIVER_DECLARED"))
        assertTrue(ids.contains("PACKER_NAME_JIAGU_NATIVE_LIBRARY"))
        assertTrue(report.riskScore >= 45)
        assertTrue(report.isSuspicious)
        assertTrue(report.limitations.any { it.contains("Known-bad certificate fingerprint list: DISABLED") })
    }

    @Test fun matchingStaticApiMarkerAvoidsClaimingPermissionUsageMismatch() {
        val report = DeepStaticAnalyzer.analyzeObservations(
            requestedPermissions = setOf("android.permission.READ_SMS"),
            hasAccessibilityService = false,
            deviceAdminReceivers = emptyList(),
            components = emptyList(),
            debugCertificate = false,
            signerMaterialAvailable = true,
            entryNames = emptySet(),
            dexSamples = listOf(DeepStaticDexSample("classes.dex", "Landroid/telephony/SmsMessage;".toByteArray(Charsets.ISO_8859_1))),
            archiveIssues = emptyList()
        )
        assertFalse(report.findings.any { it.ruleId == "REQUESTED_PERMISSION_API_REFERENCE_MISMATCH" })
    }

    @Test fun absentKnownApiReferenceIsLowConfidenceAndExplainsLimits() {
        val report = DeepStaticAnalyzer.analyzeObservations(
            requestedPermissions = setOf("android.permission.READ_SMS"),
            hasAccessibilityService = false,
            deviceAdminReceivers = emptyList(),
            components = emptyList(),
            debugCertificate = false,
            signerMaterialAvailable = true,
            entryNames = emptySet(),
            dexSamples = listOf(DeepStaticDexSample("classes.dex", ByteArray(128))),
            archiveIssues = emptyList()
        )
        val finding = report.findings.single { it.ruleId == "REQUESTED_PERMISSION_API_REFERENCE_MISMATCH" }
        assertTrue(finding.confidence <= 30)
        assertTrue(finding.evidence.contains("Reflection, native calls"))
    }

    @Test fun malformedArchiveIsReportedAsIncompleteNotAsClean() {
        val file = File.createTempFile("deep-static-malformed", ".apk")
        try {
            file.writeText("not a zip archive")
            val report = DeepStaticAnalyzer().analyze(null, file)
            assertTrue(report.findings.any { it.ruleId == "APK_ARCHIVE_UNREADABLE" })
        } finally {
            file.delete()
        }
    }
}