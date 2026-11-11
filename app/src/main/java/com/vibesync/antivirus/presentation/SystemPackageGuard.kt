package com.vibesync.antivirus.presentation

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import com.vibesync.antivirus.core.security.ProtectedPackagePolicy
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist

sealed class PackageGuardResult {
    object Allowed : PackageGuardResult()
    data class BlockedSystemApp(val reason: String) : PackageGuardResult()
    object NotFound : PackageGuardResult()
}

object SystemPackageGuard {
    fun isSystemFlags(flags: Int): Boolean =
        TrustedPackageWhitelist.hasSystemFlags(flags)

    fun evaluateFlags(flags: Int, isActiveDeviceAdmin: Boolean = false): PackageGuardResult =
        when {
            isSystemFlags(flags) -> PackageGuardResult.BlockedSystemApp("system")
            isActiveDeviceAdmin -> PackageGuardResult.BlockedSystemApp("admin")
            else -> PackageGuardResult.Allowed
        }

    fun isUserInstalled(context: Context, raw: String): Boolean {
        val packageName = normalizePackageName(raw) ?: return false
        val info = try {
            getApplicationInfo(context.packageManager, packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            return false
        } catch (_: SecurityException) {
            return false
        }
        return ProtectedPackagePolicy.isUserInstalled(info.flags, packageName, context.packageName)
    }

    fun evaluate(context: Context, raw: String): PackageGuardResult {
        val packageName = normalizePackageName(raw) ?: return PackageGuardResult.NotFound
        val pm = context.packageManager
        val info = try {
            getApplicationInfo(pm, packageName)
        } catch (_: PackageManager.NameNotFoundException) {
            return PackageGuardResult.NotFound
        } catch (_: SecurityException) {
            return PackageGuardResult.NotFound
        }

        if (!ProtectedPackagePolicy.isUserInstalled(info.flags, packageName, context.packageName)) {
            return PackageGuardResult.BlockedSystemApp("system")
        }
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        if (dpm != null) {
            val admins = runCatching { dpm.activeAdmins.orEmpty() }
                .getOrDefault(emptyList<ComponentName>())
            if (admins.any {
                    it.packageName == packageName &&
                        runCatching { dpm.isAdminActive(it) }.getOrDefault(false)
                }
            ) return PackageGuardResult.BlockedSystemApp("admin")
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { pm.getInstallSourceInfo(packageName).installingPackageName }
        }
        return PackageGuardResult.Allowed
    }

    @Suppress("DEPRECATION")
    private fun getApplicationInfo(pm: PackageManager, packageName: String): ApplicationInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0L))
        } else {
            pm.getApplicationInfo(packageName, 0)
        }

    fun normalizePackageName(value: String?): String? {
        val packageName = value?.trim() ?: return null
        if (packageName.isBlank() || packageName.length > 255 ||
            !packageName.matches(Regex("^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+$"))
        ) return null
        return packageName
    }
}

