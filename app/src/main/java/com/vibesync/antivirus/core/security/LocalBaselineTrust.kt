package com.vibesync.antivirus.core.security

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability

data class LocalBaselineObservations(
    val buildTags: String?,
    val bootloaderLocked: Boolean?,
    val adbEnabled: Boolean?,
    val googlePlayServicesAvailable: Boolean?
)

data class LocalBaselineReport(val trusted: Boolean, val reasons: List<String>)

/**
 * Conservative device-local posture heuristic. It is distinct from Google's server-decoded
 * Play Integrity verdict and cannot prove device integrity or app authenticity.
 */
object LocalBaselineTrust {
    fun shouldUseLocalBaseline(endpoint: String, validatedInternet: Boolean): Boolean =
        endpoint.isBlank() || !validatedInternet

    fun evaluate(observations: LocalBaselineObservations): LocalBaselineReport {
        val reasons = mutableListOf<String>()
        val tags = observations.buildTags?.trim()
        when {
            tags.isNullOrEmpty() -> reasons += "Build tags could not be read."
            tags.contains("test-keys", ignoreCase = true) -> reasons += "Build tags contain test-keys."
        }
        when (observations.bootloaderLocked) {
            true -> Unit
            false -> reasons += "Bootloader or verified-boot state indicates an unlocked/untrusted device."
            null -> reasons += "Bootloader lock state could not be verified."
        }
        when (observations.adbEnabled) {
            true -> reasons += "ADB debugging is enabled."
            false -> Unit
            null -> reasons += "ADB debugging state could not be read."
        }
        when (observations.googlePlayServicesAvailable) {
            true -> Unit
            false -> reasons += "Google Play Services is unavailable or needs an update."
            null -> reasons += "Google Play Services availability could not be determined."
        }
        return LocalBaselineReport(trusted = reasons.isEmpty(), reasons = reasons)
    }

    fun evaluate(context: Context): LocalBaselineReport {
        val app = context.applicationContext
        val adbEnabled = runCatching {
            Settings.Global.getInt(app.contentResolver, Settings.Global.ADB_ENABLED, -1)
                .takeIf { it >= 0 }?.let { it != 0 }
        }.getOrNull()
        val googlePlayServicesAvailable = runCatching {
            GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(app) ==
                ConnectionResult.SUCCESS
        }.getOrNull()
        return evaluate(
            LocalBaselineObservations(
                buildTags = Build.TAGS,
                bootloaderLocked = readBootloaderLocked(),
                adbEnabled = adbEnabled,
                googlePlayServicesAvailable = googlePlayServicesAvailable
            )
        )
    }

    /** Only verified-boot states or explicit lock properties can establish a locked bootloader. */
    private fun readBootloaderLocked(): Boolean? {
        val verifiedBootState = readSystemProperty("ro.boot.verifiedbootstate")?.lowercase()
        val flashLocked = readSystemProperty("ro.boot.flash.locked")
        val vbmetaState = readSystemProperty("ro.boot.vbmeta.device_state")?.lowercase()
        return when {
            verifiedBootState == "orange" || verifiedBootState == "red" -> false
            flashLocked == "0" || vbmetaState == "unlocked" -> false
            verifiedBootState == "green" || verifiedBootState == "yellow" -> true
            flashLocked == "1" || vbmetaState == "locked" -> true
            else -> null
        }
    }

    private fun readSystemProperty(name: String): String? {
        val reflected = runCatching {
            val properties = Class.forName("android.os.SystemProperties")
            properties.getMethod("get", String::class.java).invoke(null, name) as? String
        }.getOrNull()?.trim()?.takeIf { it.isNotEmpty() }
        if (reflected != null) return reflected
        // SystemProperties is a non-SDK API; use Android's read-only getprop utility as fallback.
        return runCatching {
            val process = ProcessBuilder("/system/bin/getprop", name).redirectErrorStream(true).start()
            process.inputStream.bufferedReader().use { it.readText() }.trim().takeIf { it.isNotEmpty() }
        }.getOrNull()
    }

    /** A validated capability check treats captive portals as offline for remote attestation. */
    fun hasValidatedInternet(context: Context): Boolean = runCatching {
        val manager = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? ConnectivityManager ?: return@runCatching false
        val network = manager.activeNetwork ?: return@runCatching false
        val capabilities = manager.getNetworkCapabilities(network) ?: return@runCatching false
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }.getOrDefault(false)
}
