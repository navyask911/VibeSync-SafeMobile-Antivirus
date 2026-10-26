package com.vibesync.antivirus.core.security

import android.content.pm.ApplicationInfo

/** Only ordinary user-installed apps are eligible for app-risk review or removal actions. */
object ProtectedPackagePolicy {
    private val protectedPackagePrefixes = listOf("com.android.", "com.google.android.", "android.")

    private val protectedPackages = setOf(
        "android",
        "com.android.systemui",
        "com.android.settings",
        "com.android.phone",
        "com.android.server.telecom",
        "com.android.providers.settings",
        "com.android.providers.media",
        "com.android.providers.downloads",
        "com.android.providers.telephony",
        "com.android.packageinstaller",
        "com.google.android.packageinstaller",
        "com.android.permissioncontroller",
        "com.google.android.permissioncontroller",
        "com.android.documentsui",
        "com.android.shell",
        "com.android.carrierconfig",
        "com.google.android.carrier",
        "com.google.android.carrierconfig",
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
        "com.google.android.googlequicksearchbox"
    )

    fun isUserInstalled(flags: Int, packageName: String, ownPackageName: String? = null): Boolean {
        val systemFlags = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        return flags and systemFlags == 0 &&
            packageName !in protectedPackages &&
            protectedPackagePrefixes.none { prefix -> packageName.startsWith(prefix) } &&
            packageName != ownPackageName
    }
}
