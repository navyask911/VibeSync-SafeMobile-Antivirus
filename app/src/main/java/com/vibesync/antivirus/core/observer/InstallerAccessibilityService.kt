package com.vibesync.antivirus.core.observer

import android.accessibilityservice.AccessibilityService
import android.view.Gravity
import android.view.WindowManager
import android.graphics.PixelFormat
import android.graphics.Color
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.accessibility.AccessibilityEvent
import android.widget.TextView
import com.vibesync.antivirus.R

/**
 * Optional, advisory-only installer reminder.
 *
 * The overlay is a short, non-focusable, non-touchable banner. It never reads window contents,
 * performs global actions, clicks controls, consumes touches, or attempts to stop installation.
 * Android may require a user to enable this service through Restricted settings for sideloaded apps.
 */
class InstallerAccessibilityService : AccessibilityService() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var banner: View? = null
    private var windowManager: WindowManager? = null
    private val dismissBanner = Runnable { removeBanner() }

    override fun onServiceConnected() {
        super.onServiceConnected()
        windowManager = getSystemService(WINDOW_SERVICE) as? WindowManager
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event?.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) return
        val packageName = event.packageName?.toString() ?: return
        if (packageName in INSTALLER_PACKAGES) {
            showAdvisoryBanner()
        } else {
            removeBanner()
        }
    }

    private fun showAdvisoryBanner() {
        mainHandler.removeCallbacks(dismissBanner)
        if (banner == null) {
            val warning = TextView(this).apply {
                text = getString(R.string.installer_unscanned_warning)
                setTextColor(Color.WHITE)
                setBackgroundColor(Color.rgb(31, 48, 61))
                setPadding(dp(16), dp(12), dp(16), dp(12))
                textSize = 15f
                maxLines = 3
                contentDescription = text
                elevation = dp(8).toFloat()
            }
            val params = WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT
            ).apply {
                gravity = Gravity.TOP or Gravity.CENTER_HORIZONTAL
                y = dp(28)
            }
            runCatching {
                windowManager?.addView(warning, params)
                banner = warning
            }
        }
        // Automatically disappear; the banner never captures any input from the installer.
        mainHandler.postDelayed(dismissBanner, BANNER_DURATION_MS)
    }

    private fun removeBanner() {
        mainHandler.removeCallbacks(dismissBanner)
        val view = banner ?: return
        banner = null
        runCatching { windowManager?.removeView(view) }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    override fun onInterrupt() = removeBanner()

    override fun onDestroy() {
        removeBanner()
        mainHandler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private companion object {
        const val BANNER_DURATION_MS = 6_000L
        val INSTALLER_PACKAGES = setOf(
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.android.permissioncontroller",
            "com.google.android.permissioncontroller"
        )
    }
}
