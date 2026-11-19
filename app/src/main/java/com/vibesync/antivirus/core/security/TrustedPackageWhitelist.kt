package com.vibesync.antivirus.core.security

import android.content.pm.ApplicationInfo
import android.content.Context
import android.util.Log

/**
 * Management protection is not a verdict. Only signer-verified Google packages are
 * included from the platform namespace; unsigned Google-named user APKs remain reviewable
 * as ordinary third-party apps and are never automatically marked clean.
 */
object TrustedPackageWhitelist {
    private val prefixes = listOf(
        "com.google.android.", "com.android.", "com.google.",
        "com.oppo.", "com.coloros.", "android."
    )
    private val packages = setOf("android", "com.android.vending")

    fun hasProtectedNamespace(packageName: String): Boolean =
        packageName in packages || prefixes.any { packageName.startsWith(it) }

    fun hasSystemFlags(flags: Int): Boolean =
        flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

    fun isProtected(flags: Int, packageName: String): Boolean =
        hasSystemFlags(flags) || hasProtectedNamespace(packageName)

    /**
     * Pure package eligibility seam shared with the Context/PackageManager adapter.
     * Unverified Google-named user APKs may be scanned as ordinary apps, but are never
     * treated as official Google apps or normalized to Clean & Safe.
     */
    fun isEligibleForReview(
        packageName: String,
        scannerPackageName: String,
        applicationFlags: Int,
        officialGoogle: Boolean
    ): Boolean {
        if (packageName == scannerPackageName) return false
        val system = hasSystemFlags(applicationFlags)
        val googleNamespace = OfficialGoogleAppPolicy.isGooglePackageName(packageName)
        return (googleNamespace && officialGoogle) ||
            (googleNamespace && !system) ||
            (!system && !hasProtectedNamespace(packageName))
    }

    fun isEligibleForReview(context: Context, packageName: String): Boolean {
        if (packageName == context.packageName) return false
        return try {
            @Suppress("DEPRECATION")
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            val googleNamespace = OfficialGoogleAppPolicy.isGooglePackageName(packageName)
            val officialGoogle = googleNamespace &&
                OfficialGoogleAppPolicy.isOfficialGooglePackage(context, packageName)
            isEligibleForReview(packageName, context.packageName, info.flags, officialGoogle)
        } catch (error: Exception) {
            val userId = android.os.Process.myUid() / 100000
            Log.e("ScanDebug", "pkg_fail pkg=$packageName stage=resolve userId=$userId", error)
            false
        }
    }
}
