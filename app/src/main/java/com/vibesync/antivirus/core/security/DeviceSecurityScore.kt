package com.vibesync.antivirus.core.security

/** A transparent configuration score, not a claim that a device is malware-free. */
data class DeviceSecuritySignals(
    val playProtectEnabled: Boolean? = null,
    val databaseUpdatedAt: Long? = null,
    val nonSystemAccessibilityApps: Int? = null,
    val nonSystemDeviceAdmins: Int? = null
)
data class DeviceSecurityAssessment(val score: Int, val signals: DeviceSecuritySignals, val databaseStale: Boolean) {
    val unknownChecks: Int get() = listOf(signals.playProtectEnabled, signals.nonSystemAccessibilityApps,
        signals.nonSystemDeviceAdmins).count { it == null }
}
object DeviceSecurityScore {
    const val FRESHNESS_MS = 24L * 60 * 60 * 1000
    fun evaluate(signals: DeviceSecuritySignals, now: Long): DeviceSecurityAssessment {
        val updated = signals.databaseUpdatedAt
        val stale = updated == null || updated <= 0L || updated > now || now - updated >= FRESHNESS_MS
        val deductions = (if (signals.playProtectEnabled == false) 20 else 0) +
            (if (stale) 10 else 0) + (if ((signals.nonSystemAccessibilityApps ?: 0) > 0) 20 else 0) +
            (if ((signals.nonSystemDeviceAdmins ?: 0) > 0) 20 else 0)
        return DeviceSecurityAssessment((100 - deductions).coerceIn(0, 100), signals, stale)
    }
}
