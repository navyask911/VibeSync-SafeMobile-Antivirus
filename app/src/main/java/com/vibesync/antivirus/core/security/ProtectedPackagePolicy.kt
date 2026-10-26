package com.vibesync.antivirus.core.security

/** Only ordinary user-installed apps are eligible for consumer risk review or removal actions. */
object ProtectedPackagePolicy {
    fun isUserInstalled(flags: Int, packageName: String, ownPackageName: String? = null): Boolean =
        !TrustedPackageWhitelist.isProtected(flags, packageName) && packageName != ownPackageName
}
