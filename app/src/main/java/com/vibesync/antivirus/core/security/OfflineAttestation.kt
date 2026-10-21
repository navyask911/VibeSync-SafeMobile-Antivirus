package com.vibesync.antivirus.core.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.InputStream
import java.security.MessageDigest
import java.util.Locale

data class OfflineAttestationResult(val verified: Boolean, val reason: String, val sha256: String? = null)

/** Expected digests must come from independently trusted configuration, not the asset being checked. */
class OfflineAttestation(private val context: Context) {
    fun verifyOwnSigner(expectedCertificateSha256: String?): OfflineAttestationResult {
        val expected = normalizeSha256(expectedCertificateSha256)
            ?: return OfflineAttestationResult(false, "No trusted expected signer fingerprint is configured.")
        val info = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES
                    else PackageManager.GET_SIGNATURES
                )
            }
        } catch (_: Exception) { return OfflineAttestationResult(false, "Application signing information is unavailable.") }
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty()
        } else {
            @Suppress("DEPRECATION")
            info.signatures?.map { it.toByteArray() }.orEmpty()
        }
        if (signatures.isEmpty()) return OfflineAttestationResult(false, "No APK signer certificate was reported.")
        val digests = signatures.map(::sha256Hex)
        val match = digests.firstOrNull { constantTimeEqualsHex(expected, it) }
        return if (match != null) OfflineAttestationResult(true, "APK signer matches external pin.", match)
        else OfflineAttestationResult(false, "APK signer does not match expected fingerprint.", digests.firstOrNull())
    }

    fun verifyAsset(assetName: String, expectedSha256: String?): OfflineAttestationResult {
        val expected = normalizeSha256(expectedSha256)
            ?: return OfflineAttestationResult(false, "No trusted expected asset digest is configured.")
        val actual = try { context.assets.open(assetName).use { it.sha256Hex() } }
        catch (_: Exception) { return OfflineAttestationResult(false, "Required asset is missing or unreadable: " + assetName) }
        return if (constantTimeEqualsHex(expected, actual)) {
            OfflineAttestationResult(true, "Asset digest matches external expected value.", actual)
        } else OfflineAttestationResult(false, "Asset SHA-256 mismatch: " + assetName, actual)
    }
    companion object {
        internal fun sha256Hex(bytes: ByteArray): String =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        internal fun normalizeSha256(value: String?): String? {
            val normalized = value?.trim()?.lowercase(Locale.ROOT) ?: return null
            return normalized.takeIf { it.matches(Regex("^[a-f0-9]{64}$")) }
        }
        internal fun constantTimeEqualsHex(expected: String, actual: String): Boolean =
            MessageDigest.isEqual(expected.toByteArray(Charsets.US_ASCII), actual.toByteArray(Charsets.US_ASCII))
        private fun InputStream.sha256Hex(): String {
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(8192)
            while (true) {
                val n = read(buffer)
                if (n < 0) break
                if (n > 0) digest.update(buffer, 0, n)
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }
    }
}
