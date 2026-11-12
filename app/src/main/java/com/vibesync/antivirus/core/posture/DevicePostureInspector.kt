package com.vibesync.antivirus.core.posture

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import com.vibesync.antivirus.core.security.TrustedPackageWhitelist

/** Reads permission/service metadata only. Never binds to an accessibility or notification service. */
class DevicePostureInspector(context: Context) {
    private val app = context.applicationContext
    private val pm = app.packageManager

    fun inspect(): DevicePostureReport {
        val findings = mutableListOf<PostureFinding>()
        val unavailable = mutableSetOf<PostureAccess>()
        fun collect(access: PostureAccess, read: () -> List<PostureFinding>) {
            try {
                findings += read().filter { candidate ->
                    if (TrustedPackageWhitelist.hasProtectedNamespace(candidate.packageName)) return@filter false
                    if (candidate.systemApp != false) {
                        // Inaccessible metadata is unknown, not approval for third-party review.
                        if (candidate.systemApp == null) unavailable += access
                        return@filter false
                    }
                    TrustedPackageWhitelist.isEligibleForReview(app, candidate.packageName)
                }
            } catch (_: Exception) { unavailable += access }
        }
        collect(PostureAccess.ACCESSIBILITY) {
            val manager = app.getSystemService(AccessibilityManager::class.java) ?: error("Accessibility metadata unavailable")
            manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK).map { service ->
                val info = service.resolveInfo?.serviceInfo ?: error("Accessibility service metadata unavailable")
                finding(PostureAccess.ACCESSIBILITY, info.packageName, ComponentName(info.packageName, info.name),
                    known = info.applicationInfo).copy(canReadScreen =
                    service.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0)
            }
        }
        collect(PostureAccess.NOTIFICATION_LISTENER) {
            // Same read-only setting used by AndroidX NotificationManagerCompat. No notification content is read.
            val enabled = Settings.Secure.getString(app.contentResolver, "enabled_notification_listeners").orEmpty()
            enabled.split(':').filter { it.isNotBlank() }.map { token ->
                val component = ComponentName.unflattenFromString(token) ?: error("Listener metadata unavailable")
                finding(PostureAccess.NOTIFICATION_LISTENER, component.packageName, component)
            }
        }
        return DevicePostureReport(findings.distinctBy { Triple(it.access, it.packageName, it.componentName) }
            .sortedWith(compareByDescending<PostureFinding> { it.nonSystemHighRisk }.thenBy { it.appName.lowercase() }),
            unavailable, System.currentTimeMillis())
    }

    private fun finding(access: PostureAccess, name: String, component: ComponentName? = null,
                        known: ApplicationInfo? = null): PostureFinding {
        val info = known ?: runCatching {
            @Suppress("DEPRECATION")
            pm.getApplicationInfo(name, 0)
        }.getOrNull()
        val isSystem = info?.let { TrustedPackageWhitelist.isProtected(it.flags, name) }
            ?: if (TrustedPackageWhitelist.hasProtectedNamespace(name)) true else null
        return PostureFinding(access, name, info?.let { runCatching { it.loadLabel(pm).toString().take(160) }.getOrNull() } ?: name,
            component?.flattenToString(), isSystem)
    }
}
