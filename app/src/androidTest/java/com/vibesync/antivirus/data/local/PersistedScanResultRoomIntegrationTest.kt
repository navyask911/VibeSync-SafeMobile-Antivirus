package com.vibesync.antivirus.data.local

import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanSource
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.security.OfficialGoogleAppPolicy
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist
import com.vibesync.antivirus.data.repository.PersistedScanResultPolicy
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PersistedScanResultRoomIntegrationTest {
    @Test
    fun roomRowsAreNormalizedAndFilteredConsistentlyForScanLabAndReport() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            val dao = database.threatDao()
            val sessionId = "persisted-result-selector-integration"
            val scannerPackage = context.packageName
            val googlePackage = "com.google.android.apps.maps"
            val ordinaryUserPackage = "com.example.userapp"
            val sideloadedGooglePrefix = "com.google.fake.userapp"
            val spoofedGoogleSystemPackage = "com.google.fake.systemapp"
            val oemSystemPackage = "com.oem.settings"
            val platformFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
            val flagsByPackage = mapOf(
                googlePackage to platformFlags,
                ordinaryUserPackage to 0,
                sideloadedGooglePrefix to 0,
                spoofedGoogleSystemPackage to ApplicationInfo.FLAG_SYSTEM,
                oemSystemPackage to platformFlags,
                scannerPackage to 0
            )
            val trustedGoogleSigner = setOf("trusted-google-release-certificate")
            val signerDigestsByPackage = mapOf(
                googlePackage to trustedGoogleSigner,
                spoofedGoogleSystemPackage to setOf("attacker-certificate"),
                sideloadedGooglePrefix to setOf("attacker-certificate")
            )

            val rows = listOf(
                ScanSessionItemEntity(
                    sessionId, "app:$googlePackage", "app", "Maps", "SUSPICIOUS",
                    packageName = googlePackage, reasons = "stale cached heuristic",
                    riskScore = 94f, detectionSource = "YARA", malwareName = "stale-cache",
                    threatEventId = "stale-threat-id", durationMs = 99L,
                    completedAt = 1_100L, apkSizeBytes = 8_192L,
                    scanSource = "CACHE_HIT", analysisStages = "CACHE_HIT"
                ),
                ScanSessionItemEntity(
                    sessionId, "app:$ordinaryUserPackage", "app", "User app", "NO_MATCH",
                    packageName = ordinaryUserPackage, completedAt = 1_120L,
                    durationMs = 52L, apkSizeBytes = 4_096L
                ),
                ScanSessionItemEntity(
                    sessionId, "app:$sideloadedGooglePrefix", "app", "Sideloaded prefix", "SUSPICIOUS",
                    packageName = sideloadedGooglePrefix, reasons = "ordinary app assessment",
                    riskScore = 70f, completedAt = 1_130L
                ),
                ScanSessionItemEntity(
                    sessionId, "app:$spoofedGoogleSystemPackage", "app", "Spoofed system package", "THREAT",
                    packageName = spoofedGoogleSystemPackage, riskScore = 100f,
                    completedAt = 1_140L
                ),
                ScanSessionItemEntity(
                    sessionId, "app:$oemSystemPackage", "app", "OEM settings", "SUSPICIOUS",
                    packageName = oemSystemPackage, riskScore = 75f, completedAt = 1_150L
                ),
                ScanSessionItemEntity(
                    sessionId, "app:$scannerPackage", "app", "SafeMobile", "NO_MATCH",
                    packageName = scannerPackage, completedAt = 1_160L
                ),
                ScanSessionItemEntity(
                    sessionId, "file:selected-document", "file", "selected-document.apk", "NO_MATCH",
                    packageName = null, completedAt = 1_170L
                )
            )
            rows.forEach { dao.insertScanSessionItem(it) }

            // Rehydrate the values from Room before applying the same result normalization
            // and visibility policy used by ThreatRepository and DeepScanWorker.
            val restored = dao.scanSessionItems(sessionId).map { item ->
                val verdict = ScanVerdict.valueOf(item.verdict)
                val restoredResult = ScanResult(
                    packageOrPath = item.itemPath,
                    displayName = item.itemPath,
                    sha256 = item.sha256Hash,
                    md5 = item.md5Hash,
                    verdict = verdict,
                    reasons = item.reasons.split("\n").filter { it.isNotBlank() },
                    durationMs = item.durationMs,
                    packageName = item.packageName,
                    threatEventId = item.threatEventId,
                    riskScore = item.riskScore,
                    malwareName = item.malwareName,
                    apkSizeBytes = item.apkSizeBytes,
                    scanSource = ScanSource.valueOf(item.scanSource),
                    analysisStages = item.analysisStages.split(",").filter { it.isNotBlank() }
                )
                val packageName = item.packageName
                val signerVerified = packageName != null &&
                    OfficialGoogleAppPolicy.hasTrustedSigner(
                        packageName,
                        signerDigestsByPackage[packageName].orEmpty(),
                        trustedGoogleSigner
                    )
                PersistedScanResultPolicy.normalizeOfficialGoogleResult(restoredResult, signerVerified)
            }

            val visible = PersistedScanResultPolicy.selectVisiblePersistedResults(restored) { result ->
                val packageName = result.packageName ?: return@selectVisiblePersistedResults true
                val flags = flagsByPackage[packageName] ?: return@selectVisiblePersistedResults false
                val signerVerified = OfficialGoogleAppPolicy.hasTrustedSigner(
                    packageName,
                    signerDigestsByPackage[packageName].orEmpty(),
                    trustedGoogleSigner
                )
                TrustedPackageWhitelist.isEligibleForReview(
                    packageName, scannerPackage, flags, signerVerified
                )
            }

            val visiblePackages = visible.mapNotNull { it.packageName }.toSet()
            assertEquals(
                setOf(googlePackage, ordinaryUserPackage, sideloadedGooglePrefix),
                visiblePackages
            )
            assertEquals(1, visible.count { it.packageName == null })
            assertTrue(visible.none { it.packageName == oemSystemPackage })
            assertTrue(visible.none { it.packageName == spoofedGoogleSystemPackage })
            assertTrue(visible.none { it.packageName == scannerPackage })

            val cleanGoogle = visible.single { it.packageName == googlePackage }
            assertEquals(ScanVerdict.NO_MATCH, cleanGoogle.verdict)
            assertEquals(ScanSource.GOOGLE_VERIFIED, cleanGoogle.scanSource)
            assertEquals(0f, cleanGoogle.riskScore, 0f)
            assertFalse(cleanGoogle.reasons.any { it.contains("stale") })
            assertTrue(cleanGoogle.reasons.single().contains("Clean & Safe"))

            val reportRows = PersistedScanResultPolicy.selectVisiblePersistedResults(restored) { result ->
                val packageName = result.packageName ?: return@selectVisiblePersistedResults true
                val flags = flagsByPackage[packageName] ?: return@selectVisiblePersistedResults false
                val signerVerified = OfficialGoogleAppPolicy.hasTrustedSigner(
                    packageName,
                    signerDigestsByPackage[packageName].orEmpty(),
                    trustedGoogleSigner
                )
                TrustedPackageWhitelist.isEligibleForReview(
                    packageName, scannerPackage, flags, signerVerified
                )
            }
            assertEquals(
                visible.map { it.packageName to it.verdict },
                reportRows.map { it.packageName to it.verdict }
            )
        } finally {
            database.close()
        }
    }
}
