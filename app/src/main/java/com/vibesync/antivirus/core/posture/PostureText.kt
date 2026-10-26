package com.vibesync.antivirus.core.posture

import com.vibesync.antivirus.R

object PostureText {
    fun title(access: PostureAccess): Int = when (access) {
        PostureAccess.ACCESSIBILITY -> R.string.posture_accessibility
        PostureAccess.DEVICE_ADMIN -> R.string.posture_administrators
        PostureAccess.NOTIFICATION_LISTENER -> R.string.posture_listeners
        PostureAccess.OVERLAY -> R.string.posture_overlays
    }
    fun explanation(finding: PostureFinding): Int = when (finding.access) {
        PostureAccess.ACCESSIBILITY -> if (finding.canReadScreen == true) R.string.posture_screen_content else R.string.posture_accessibility_power
        PostureAccess.DEVICE_ADMIN -> R.string.posture_admin_power
        PostureAccess.NOTIFICATION_LISTENER -> R.string.posture_notification_power
        PostureAccess.OVERLAY -> R.string.posture_overlay_power
    }
}
