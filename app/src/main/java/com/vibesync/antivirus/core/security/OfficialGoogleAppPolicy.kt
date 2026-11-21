package com.vibesync.antivirus.core.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest
import java.util.WeakHashMap

/**
 * Trust requires both a Google package namespace/known name and a signer matching
 * an installed system Google Play Services or Play Store signing anchor.
 */
object OfficialGoogleAppPolicy {
    private val exactGooglePackages = setOf("com.android.chrome", "com.android.vending")
    private val signerAnchors = listOf("com.google.android.gms", "com.android.vending")
    private val trustedSignerCache = WeakHashMap<PackageManager, Set<String>>()

    fun isGooglePackageName(packageName: String): Boolean =
        packageName.startsWith("com.google.") || packageName in exactGooglePackages

    /**
     * Pure inclusion guard used by inventory classification: platform apps are eligible
     * only when the Google signer policy has already verified them.
     */
    fun isEligibleForInstalledScan(
        packageName: String,
        scannerPackageName: String,
        applicationFlags: Int,
        officialGoogle: Boolean
    ): Boolean {
        if (packageName == scannerPackageName) return false
        val platformFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        val isPlatformApp = applicationFlags and platformFlags != 0
        return (officialGoogle && isGooglePackageName(packageName)) || !isPlatformApp
    }

    fun hasTrustedSigner(
        packageName: String,
        candidateDigests: Set<String>,
        trustedDigests: Set<String>
    ): Boolean = isGooglePackageName(packageName) &&
        candidateDigests.any { it in trustedDigests }

    fun isOfficialGooglePackage(
        context: Context,
        packageName: String,
        suppliedInfo: PackageInfo? = null
    ): Boolean {
        if (!isGooglePackageName(packageName)) return false
        val packageManager = context.packageManager
        val trusted = trustedSignerDigests(packageManager)
        if (trusted.isEmpty()) return false
        val suppliedDigests = suppliedInfo?.let(::signingCertificateDigests).orEmpty()
        val candidate = if (suppliedDigests.isNotEmpty()) suppliedInfo
            else loadPackageInfo(packageManager, packageName)
        val candidateDigests = candidate?.let(::signingCertificateDigests).orEmpty()
        return hasTrustedSigner(packageName, candidateDigests, trusted)
    }

    private fun trustedSignerDigests(packageManager: PackageManager): Set<String> =
        synchronized(trustedSignerCache) {
            trustedSignerCache[packageManager]?.let { return@synchronized it }
            val trusted = signerAnchors.flatMap { anchor ->
                try {
                    @Suppress("DEPRECATION")
                    val appInfo = packageManager.getApplicationInfo(anchor, 0)
                    val platformFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
                    if (appInfo.flags and platformFlags == 0) emptyList()
                    else loadPackageInfo(packageManager, anchor)?.let(::signingCertificateDigests).orEmpty().toList()
                } catch (_: Exception) {
                    emptyList()
                }
            }.toSet()
            if (trusted.isNotEmpty()) trustedSignerCache[packageManager] = trusted
            trusted
        }

    private fun loadPackageInfo(packageManager: PackageManager, packageName: String): PackageInfo? =
        try {
            val flags = signingFlags()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, flags)
            }
        } catch (_: Exception) {
            null
        }

    private fun signingFlags(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) PackageManager.GET_SIGNING_CERTIFICATES
        else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }

    private fun signingCertificateDigests(info: PackageInfo): Set<String> {
        val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = info.signingInfo
            if (signingInfo == null) emptyList()
            else (signingInfo.apkContentsSigners?.toList().orEmpty() +
                signingInfo.signingCertificateHistory?.toList().orEmpty()).distinct()
        } else {
            @Suppress("DEPRECATION")
            info.signatures?.toList().orEmpty()
        }
        return signatures.mapNotNull { signature ->
            runCatching {
                MessageDigest.getInstance("SHA-256").digest(signature.toByteArray())
                    .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            }.getOrNull()
        }.toSet()
    }
}
