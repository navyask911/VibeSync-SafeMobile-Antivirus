package com.vibesync.antivirus.core.security

import android.content.pm.ApplicationInfo
import android.content.Context
import android.util.Log

/**
 * Installed-app review is limited to ordinary third-party user apps. Google and
 * protected OEM/platform namespaces stay excluded, even when packages are signer-verified.
 */
object TrustedPackageWhitelist {
    private val prefixes = listOf(
        "com.google.android.", "com.android.", "com.google.",
        "com.oppo.", "com.coloros.", "com.oplus.", "com.oneplus.",
        "com.samsung.", "com.miui.", "com.xiaomi.", "com.vivo.", "com.iqoo.",
        "com.huawei.", "com.honor.", "com.motorola.", "com.lenovo.",
        "com.lge.", "com.sony.", "com.asus.", "com.realme.",
        "com.transsion.", "com.infinix.", "com.tecno.", "com.nothing.",
        "com.zte.", "com.tcl.", "android."
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
     * All Google, Android and OEM namespaces are excluded regardless of signer verification;
     * ordinary third-party user-installed packages remain reviewable.
     */
    @Suppress("UNUSED_PARAMETER")
    fun isEligibleForReview(
        packageName: String,
        scannerPackageName: String,
        applicationFlags: Int,
        officialGoogle: Boolean
    ): Boolean {
        if (packageName == scannerPackageName) return false
        return !isProtected(applicationFlags, packageName)
    }

    fun isEligibleForReview(context: Context, packageName: String): Boolean {
        if (packageName == context.packageName) return false
        return try {
            @Suppress("DEPRECATION")
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            isEligibleForReview(packageName, context.packageName, info.flags, officialGoogle = false)
        } catch (error: Exception) {
            val userId = android.os.Process.myUid() / 100000
            Log.e("ScanDebug", "pkg_fail pkg=$packageName stage=resolve userId=$userId", error)
            false
        }
    }
}
