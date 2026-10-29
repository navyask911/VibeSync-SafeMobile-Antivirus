package com.vibesync.antivirus.core.security

/** Observations of local configuration only. Null means unverified, never "safe". */
data class DeviceSecuritySignals(
    val playProtectEnabled: Boolean? = null,
    val databaseUpdatedAt: Long? = null,
    val nonSystemAccessibilityApps: Int? = null,
    val nonSystemDeviceAdmins: Int? = null,
    val usbDebuggingEnabled: Boolean? = null,
    /** Only SafeMobile's own install-unknown-apps grant; no device-wide API exists. */
    val safeMobileUnknownSourcesGrant: Boolean? = null,
    val activeNonSystemOverlays: Int? = null,
    val backgroundRestricted: Boolean? = null
)
data class DeviceSecurityAssessment(
    val score: Int,
    val signals: DeviceSecuritySignals,
    val databaseStale: Boolean
) {
    val unknownChecks: Int get() = listOf(
        signals.playProtectEnabled, signals.nonSystemAccessibilityApps,
        signals.nonSystemDeviceAdmins, signals.usbDebuggingEnabled,
        signals.safeMobileUnknownSourcesGrant, signals.activeNonSystemOverlays,
        signals.backgroundRestricted
    ).count { it == null }
}
object DeviceSecurityScore {
    const val FRESHNESS_MS = 24L * 60 * 60 * 1000

    /** Weight sum = 100. This is a posture indicator, NOT a probability of no malware.
     * Unknowns remain unverified; do not silently convert them to confirmed safety.
     */
    fun evaluate(signals: DeviceSecuritySignals, now: Long): DeviceSecurityAssessment {
        val updated = signals.databaseUpdatedAt
        val stale = updated == null || updated <= 0L || updated > now || now - updated >= FRESHNESS_MS
        val deductions =
            (if (signals.playProtectEnabled == false) 20 else 0) +
            (if (signals.usbDebuggingEnabled == true) 15 else 0) +
            (if (signals.safeMobileUnknownSourcesGrant == true) 10 else 0) +
            (if ((signals.activeNonSystemOverlays ?: 0) > 0) 15 else 0) +
            (if (signals.backgroundRestricted == true) 15 else 0) +
            (if (stale) 10 else 0) +
            (if ((signals.nonSystemAccessibilityApps ?: 0) > 0) 10 else 0) +
            (if ((signals.nonSystemDeviceAdmins ?: 0) > 0) 5 else 0)
        return DeviceSecurityAssessment((100 - deductions).coerceIn(0, 100), signals, stale)
    }
}
