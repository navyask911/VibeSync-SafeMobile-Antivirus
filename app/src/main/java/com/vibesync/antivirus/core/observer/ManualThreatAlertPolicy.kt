package com.vibesync.antivirus.core.observer

/**
 * A foreground/manual scan is an explicit user action. Confirmed malware from that scan must
 * always get an audible alarm; notification and voice preferences control optional extras only.
 */
internal object ManualThreatAlertPolicy {
    fun shouldAlert(isManualScan: Boolean, hasConfirmedThreat: Boolean): Boolean =
        isManualScan && hasConfirmedThreat
}
