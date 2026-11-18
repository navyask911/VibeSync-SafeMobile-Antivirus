package com.vibesync.antivirus.core.security

import android.content.pm.ApplicationInfo
import android.content.Context
import android.util.Log

/**
 * Installed-package exclusions from consumer app review/removal. This is a management policy,
 * not a certificate or malware-safety verdict. Downloaded APKs are not trusted by their names.
 */
object TrustedPackageWhitelist {
    private val prefixes = listOf("com.google.android.", "com.android.", "com.google.", "com.oppo.", "com.coloros.", "android.")
    private val packages = setOf("android", "com.android.vending")

    fun hasProtectedNamespace(packageName: String): Boolean =
        packageName in packages || prefixes.any { packageName.startsWith(it) }

    fun hasSystemFlags(flags: Int): Boolean =
        flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0

    fun isProtected(flags: Int, packageName: String): Boolean =
        hasSystemFlags(flags) || hasProtectedNamespace(packageName)

    fun isEligibleForReview(context: Context, packageName: String): Boolean {
        if (packageName == context.packageName || hasProtectedNamespace(packageName)) return false
        return try {
            @Suppress("DEPRECATION")
            val info = context.packageManager.getApplicationInfo(packageName, 0)
            !isProtected(info.flags, packageName)
        } catch (error: Exception) {
            val userId = android.os.UserHandle.myUserHandle().identifier
            Log.e("ScanDebug", "pkg_fail pkg=$packageName stage=resolve userId=$userId", error)
            false
        }
    }
}
