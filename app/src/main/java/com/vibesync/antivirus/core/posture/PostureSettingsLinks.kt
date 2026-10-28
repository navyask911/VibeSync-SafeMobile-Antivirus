package com.vibesync.antivirus.core.posture

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings

/** User-driven Settings navigation only. Never launches an activation or permission-grant intent. */
object PostureSettingsLinks {
    fun candidates(finding: PostureFinding): List<Intent> {
        val component = finding.componentName?.let(ComponentName::unflattenFromString)
        val intents = mutableListOf<Intent>()
        when (finding.access) {
            PostureAccess.ACCESSIBILITY -> {
                // AOSP exposes this detail action; OEMs may only expose the public category page.
                if (component != null) intents += Intent("android.settings.ACCESSIBILITY_DETAILS_SETTINGS")
                    .putExtra(Intent.EXTRA_COMPONENT_NAME, component)
                intents += Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)
            }
            PostureAccess.DEVICE_ADMIN -> {
                intents += Intent("android.settings.DEVICE_ADMIN_SETTINGS")
                intents += Intent(Settings.ACTION_SECURITY_SETTINGS)
            }
            PostureAccess.NOTIFICATION_LISTENER -> {
                if (Build.VERSION.SDK_INT >= 30 && component != null) {
                    intents += Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
                        .putExtra(Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME, component.flattenToString())
                }
                intents += Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
            }
            PostureAccess.OVERLAY -> {
                val packageName = finding.packageName
                // Package-specific on Android 10 and older; Android 11+ may ignore the URI.
                intents += Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION).apply {
                    data = Uri.parse("package:$packageName")
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                intents += Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION)
            }
        }
        intents += Intent(Settings.ACTION_SETTINGS)
        return intents
    }

    fun open(context: Context, finding: PostureFinding): Boolean {
        for (intent in candidates(finding)) {
            try {
                context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                if (finding.access == PostureAccess.OVERLAY && Build.VERSION.SDK_INT >= 30) {
                    android.widget.Toast.makeText(context,
                        context.getString(com.vibesync.antivirus.R.string.posture_overlay_select_app, finding.appName),
                        android.widget.Toast.LENGTH_LONG).show()
                }
                return true
            }
            catch (_: Exception) { /* Try the category page when an OEM lacks the detail destination. */ }
        }
        return false
    }
}
