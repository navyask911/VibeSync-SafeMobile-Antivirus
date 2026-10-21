package com.vibesync.antivirus.core.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import java.io.File

data class IntegrityReport(val isUntrusted: Boolean, val reasons: List<String>, val riskMultiplier: Float = 1.0f)
interface IntegrityProbe {
    fun pathExists(path: String): Boolean
    fun packageInstalled(packageName: String): Boolean
    fun systemProperty(name: String): String?
    fun selinuxEnforced(): Boolean?
    fun debuggerAttached(): Boolean
    fun emulatorLikely(): Boolean
}

/** Offline heuristic only. Indicators can be hidden/spoofed and do not constitute attestation. */
class IntegrityChecker private constructor(private val probe: IntegrityProbe, @Suppress("UNUSED_PARAMETER") marker: Unit) {
    constructor(context: Context) : this(AndroidIntegrityProbe(context.applicationContext), Unit)
    constructor(probe: IntegrityProbe) : this(probe, Unit)

    fun check(): IntegrityReport {
        val reasons = linkedSetOf<String>()
        var multiplier = 1.0f
        val root = ROOT_PATHS.filter(probe::pathExists)
        if (root.isNotEmpty()) {
            reasons += "Root-related filesystem indicators present (" + root.size + ")."
            multiplier += 0.20f
        }
        val hooks = HOOK_PATHS.filter(probe::pathExists)
        if (hooks.isNotEmpty()) {
            reasons += "Xposed/LSPosed/Riru indicators present (" + hooks.size + ")."
            multiplier += 0.15f
        }
        KNOWN_PACKAGES.filter(probe::packageInstalled).forEach { reasons += "Root/hook manager visible: " + it }
        if (probe.systemProperty("ro.build.tags").orEmpty().contains("test-keys", ignoreCase = true)) {
            reasons += "Build tags contain test-keys."
            multiplier += 0.10f
        }
        if (probe.systemProperty("ro.debuggable") == "1" ||
            probe.systemProperty("ro.secure") == "0" ||
            probe.systemProperty("ro.build.type") in setOf("eng", "userdebug")) {
            reasons += "Build properties indicate a debuggable or non-production build."
            multiplier += 0.10f
        }
        if (probe.selinuxEnforced() == false) {
            reasons += "SELinux is not enforcing according to the readable local status file."
            multiplier += 0.10f
        }
        if (probe.debuggerAttached()) {
            reasons += "A debugger is attached to this process."
            multiplier += 0.05f
        }
        if (probe.emulatorLikely()) {
            reasons += "Build properties resemble an emulator or test device."
            multiplier += 0.05f
        }
        return IntegrityReport(reasons.isNotEmpty(), reasons.toList(), multiplier.coerceIn(1.0f, 1.5f))
    }

    private class AndroidIntegrityProbe(private val app: Context) : IntegrityProbe {
        override fun pathExists(path: String) = runCatching { File(path).exists() }.getOrDefault(false)
        override fun packageInstalled(packageName: String): Boolean = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                app.packageManager.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0L))
            } else {
                @Suppress("DEPRECATION")
                app.packageManager.getApplicationInfo(packageName, 0)
            }
            true
        } catch (_: PackageManager.NameNotFoundException) { false }
        catch (_: SecurityException) { false }

        override fun systemProperty(name: String): String? = runCatching {
            val type = Class.forName("android.os.SystemProperties")
            type.getMethod("get", String::class.java).invoke(null, name) as? String
        }.getOrNull()?.takeIf(String::isNotBlank)

        override fun selinuxEnforced(): Boolean? = runCatching {
            val file = File("/sys/fs/selinux/enforce")
            if (!file.isFile || !file.canRead()) null else file.readText().trim() == "1"
        }.getOrNull()

        override fun debuggerAttached() = runCatching {
            Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        }.getOrDefault(false)

        override fun emulatorLikely(): Boolean {
            val fingerprint = Build.FINGERPRINT.orEmpty()
            return fingerprint.startsWith("generic", true) || fingerprint.contains("emulator", true) ||
                Build.MODEL.orEmpty().contains("Emulator", true) ||
                Build.PRODUCT.orEmpty().contains("sdk", true) ||
                Build.HARDWARE.orEmpty().contains("goldfish", true) ||
                Build.HARDWARE.orEmpty().contains("ranchu", true)
        }
    }

    companion object {
        internal val ROOT_PATHS = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/vendor/bin/su",
            "/system/app/Superuser.apk", "/data/adb/magisk", "/sbin/.magisk", "/data/adb/modules", "/debug_ramdisk")
        internal val HOOK_PATHS = listOf("/system/framework/XposedBridge.jar", "/system/lib/libxposed_art.so",
            "/system/lib64/libxposed_art.so", "/data/adb/lspd", "/data/adb/riru", "/data/adb/modules/zygisk_lsposed")
        internal val KNOWN_PACKAGES = setOf("com.topjohnwu.magisk", "eu.chainfire.supersu",
            "com.koushikdutta.superuser", "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager",
            "org.lsposed.manager", "com.saurik.substrate")
    }
}
