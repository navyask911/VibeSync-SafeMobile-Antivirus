package com.vibesync.antivirus.presentation

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.util.Log

sealed class UninstallResult {
    object Success : UninstallResult()
    object RequiresUserAction : UninstallResult()
    data class BlockedSystemApp(val reason: String) : UninstallResult()
    object NotFound : UninstallResult()
    object OpenedAppInfo : UninstallResult()
    object HandlerUnavailable : UninstallResult()
}

/**
 * Requests a user-confirmed Android uninstall. This app does not have the privileged permission
 * required to silently remove arbitrary packages, so it uses ACTION_DELETE and a safe App Info
 * fallback only.
 */
object UninstallHandler {
    private const val TAG = "SafeMobileUninstall"

    fun buildDeleteIntent(packageName: String): Intent =
        Intent(Intent.ACTION_DELETE, Uri.parse("package:${requireValidPackage(packageName)}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun buildAppInfoIntent(packageName: String): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${requireValidPackage(packageName)}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    fun request(
        context: Context,
        packageName: String,
        launchDelete: (Intent) -> Unit,
        openAppInfo: (Intent) -> Unit
    ): UninstallResult {
        val pkg = SystemPackageGuard.normalizePackageName(packageName) ?: return UninstallResult.NotFound
        when (val guard = SystemPackageGuard.evaluate(context, pkg)) {
            is PackageGuardResult.BlockedSystemApp -> return UninstallResult.BlockedSystemApp(guard.reason)
            PackageGuardResult.NotFound -> return UninstallResult.NotFound
            PackageGuardResult.Allowed -> Unit
        }
        return launchFallback(pkg, launchDelete, openAppInfo)
    }

    fun launchWithFallback(
        packageName: String,
        launchDelete: (Intent) -> Unit,
        openAppInfo: (Intent) -> Unit
    ): UninstallResult {
        val pkg = SystemPackageGuard.normalizePackageName(packageName) ?: return UninstallResult.NotFound
        return launchFallback(pkg, launchDelete, openAppInfo)
    }

    private fun launchFallback(
        pkg: String,
        launchDelete: (Intent) -> Unit,
        openAppInfo: (Intent) -> Unit
    ): UninstallResult {
        return try {
            launchDelete(buildDeleteIntent(pkg))
            UninstallResult.RequiresUserAction
        } catch (error: ActivityNotFoundException) {
            Log.w(TAG, "ACTION_DELETE unavailable; opening App Info", error)
            openSettings(pkg, openAppInfo)
        } catch (error: SecurityException) {
            Log.w(TAG, "ACTION_DELETE blocked; opening App Info", error)
            openSettings(pkg, openAppInfo)
        } catch (error: IllegalStateException) {
            Log.w(TAG, "Uninstall host not active; opening App Info", error)
            openSettings(pkg, openAppInfo)
        } catch (error: IllegalArgumentException) {
            Log.w(TAG, "ACTION_DELETE rejected; opening App Info", error)
            openSettings(pkg, openAppInfo)
        }
    }

    private fun openSettings(pkg: String, openAppInfo: (Intent) -> Unit): UninstallResult {
        return try {
            openAppInfo(buildAppInfoIntent(pkg))
            UninstallResult.OpenedAppInfo
        } catch (error: ActivityNotFoundException) {
            Log.w(TAG, "App Info unavailable", error)
            UninstallResult.HandlerUnavailable
        } catch (error: SecurityException) {
            Log.w(TAG, "App Info restricted", error)
            UninstallResult.HandlerUnavailable
        } catch (error: IllegalStateException) {
            Log.w(TAG, "App Info host not active", error)
            UninstallResult.HandlerUnavailable
        } catch (error: IllegalArgumentException) {
            Log.w(TAG, "App Info intent rejected", error)
            UninstallResult.HandlerUnavailable
        }
    }

    private fun requireValidPackage(value: String): String =
        SystemPackageGuard.normalizePackageName(value)
            ?: throw IllegalArgumentException("Invalid package name")
}
