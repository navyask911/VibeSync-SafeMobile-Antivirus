package com.vibesync.antivirus.data.repository

import android.content.pm.ApplicationInfo
import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanSource
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.security.OfficialGoogleAppPolicy
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistedScanResultPolicyTest {
    private val scannerPackage = "com.vibesync.antivirus"
    private val googlePackage = "com.google.android.apps.maps"
    private val trustedGoogleSigner = setOf("google-release-cert")

    private fun row(
        packageName: String?,
        verdict: ScanVerdict,
        source: ScanSource = ScanSource.FRESH,
        score: Float = 0f,
        malwareName: String? = null
    ) = ScanResult(
        packageOrPath = packageName ?: "selected-file.apk",
        displayName = packageName ?: "selected-file.apk",
        sha256 = "stale-hash",
        md5 = null,
        verdict = verdict,
        reasons = listOf("persisted verdict"),
        durationMs = 41L,
        packageName = packageName,
        threatEventId = if (verdict == ScanVerdict.SUSPICIOUS) "old-threat-event" else null,
        riskScore = score,
        detectionSource = if (verdict == ScanVerdict.SUSPICIOUS) DetectionSource.YARA else DetectionSource.NONE,
        malwareName = malwareName,
        mlProbability = if (verdict == ScanVerdict.SUSPICIOUS) 0.98f else null,
        confidence = 0.8f,
        apkSizeBytes = 4_096L,
        scanSource = source,
        analysisStages = listOf("CACHE_HIT")
    )

    @Test
    fun verifiedGoogleSignerOverridesStaleSuspiciousPersistedVerdict() {
        val signerVerified = OfficialGoogleAppPolicy.hasTrustedSigner(
            googlePackage,
            candidateDigests = trustedGoogleSigner,
            trustedDigests = trustedGoogleSigner
        )
        assertTrue(signerVerified)
        assertTrue(
            TrustedPackageWhitelist.isEligibleForReview(
                googlePackage,
                scannerPackage,
                ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP,
                officialGoogle = signerVerified
            )
        )

        val stale = row(
            googlePackage,
            ScanVerdict.SUSPICIOUS,
            source = ScanSource.CACHE_HIT,
            score = 92f,
            malwareName = "stale-cache-detection"
        )
        val clean = PersistedScanResultPolicy.normalizeOfficialGoogleResult(stale, signerVerified)

        assertEquals(ScanVerdict.NO_MATCH, clean.verdict)
        assertEquals(ScanSource.GOOGLE_VERIFIED, clean.scanSource)
        assertEquals(DetectionSource.NONE, clean.detectionSource)
        assertEquals(0f, clean.riskScore, 0f)
        assertNull(clean.malwareName)
        assertNull(clean.threatEventId)
        assertNull(clean.mlProbability)
        assertEquals(listOf("SIGNER_VERIFIED", "VERDICT"), clean.analysisStages)
        assertTrue(clean.reasons.single().contains("Clean & Safe"))
    }

    @Test
    fun untrustedGooglePrefixCannotBeNormalizedOrPassSystemAppEligibility() {
        val spoofedPackage = "com.google.fake.sideload"
        val signerVerified = OfficialGoogleAppPolicy.hasTrustedSigner(
            spoofedPackage,
            candidateDigests = setOf("attacker-cert"),
            trustedDigests = trustedGoogleSigner
        )
        assertFalse(signerVerified)
        assertFalse(
            TrustedPackageWhitelist.isEligibleForReview(
                spoofedPackage,
                scannerPackage,
                ApplicationInfo.FLAG_SYSTEM,
                officialGoogle = signerVerified
            )
        )

        val stale = row(spoofedPackage, ScanVerdict.SUSPICIOUS, source = ScanSource.CACHE_HIT, score = 75f)
        val unchanged = PersistedScanResultPolicy.normalizeOfficialGoogleResult(stale, signerVerified)
        assertEquals(ScanVerdict.SUSPICIOUS, unchanged.verdict)
        assertEquals(ScanSource.CACHE_HIT, unchanged.scanSource)
        assertEquals(75f, unchanged.riskScore, 0f)
    }

    @Test
    fun persistedSelectorKeepsVerifiedGoogleAndUserAppsButDropsSystemOemRows() = runBlocking {
        val userApp = "com.example.userapp"
        val oemSystem = "com.oem.settings"
        val spoofedGoogleSystem = "com.google.fake.system"
        val sideloadedGooglePrefix = "com.google.fake.user"
        val systemFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        val flags = mapOf(
            googlePackage to systemFlags,
            userApp to 0,
            oemSystem to systemFlags,
            spoofedGoogleSystem to ApplicationInfo.FLAG_SYSTEM,
            sideloadedGooglePrefix to 0,
            scannerPackage to 0
        )
        val signerDigests = mapOf(
            googlePackage to trustedGoogleSigner,
            spoofedGoogleSystem to setOf("attacker-cert"),
            sideloadedGooglePrefix to setOf("attacker-cert")
        )

        val verifiedGoogle = OfficialGoogleAppPolicy.hasTrustedSigner(
            googlePackage, signerDigests.getValue(googlePackage), trustedGoogleSigner
        )
        val normalizedGoogle = PersistedScanResultPolicy.normalizeOfficialGoogleResult(
            row(googlePackage, ScanVerdict.SUSPICIOUS, source = ScanSource.CACHE_HIT, score = 88f),
            verifiedGoogle
        )
        val persistedRows = listOf(
            row(userApp, ScanVerdict.NO_MATCH),
            normalizedGoogle,
            row(oemSystem, ScanVerdict.SUSPICIOUS, score = 70f),
            row(spoofedGoogleSystem, ScanVerdict.THREAT, score = 100f),
            row(sideloadedGooglePrefix, ScanVerdict.SUSPICIOUS, score = 70f),
            row(scannerPackage, ScanVerdict.NO_MATCH),
            row(null, ScanVerdict.NO_MATCH)
        )

        // Shared selector used by ThreatRepository for Room-restored results and by the
        // DeepScanWorker before it calculates/persists the scan report.
        val visible = PersistedScanResultPolicy.selectVisiblePersistedResults(persistedRows) { result ->
            val packageName = result.packageName ?: return@selectVisiblePersistedResults true
            val appFlags = flags[packageName] ?: return@selectVisiblePersistedResults false
            val officialGoogle = OfficialGoogleAppPolicy.hasTrustedSigner(
                packageName,
                signerDigests[packageName].orEmpty(),
                trustedGoogleSigner
            )
            TrustedPackageWhitelist.isEligibleForReview(
                packageName, scannerPackage, appFlags, officialGoogle
            )
        }

        assertEquals(
            setOf(googlePackage, userApp, sideloadedGooglePrefix, null),
            visible.map { it.packageName }.toSet()
        )
        assertEquals(ScanVerdict.NO_MATCH, visible.single { it.packageName == googlePackage }.verdict)
        assertEquals(ScanSource.GOOGLE_VERIFIED, visible.single { it.packageName == googlePackage }.scanSource)
        assertEquals(
            listOf(ScanVerdict.SUSPICIOUS, ScanVerdict.NO_MATCH, ScanVerdict.NO_MATCH, ScanVerdict.NO_MATCH),
            visible.map { it.verdict }
        )
    }
}
