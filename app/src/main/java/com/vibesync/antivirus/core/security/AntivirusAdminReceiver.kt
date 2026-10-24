package com.vibesync.antivirus.core.security

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Standard consumer Device Administrator receiver. It does not grant Device Owner privileges
 * and cannot prevent APK installation. Events are logged locally only.
 */
open class AntivirusAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        Log.i(TAG, "Device Administrator enabled")
    }

    override fun onDisabled(context: Context, intent: Intent) {
        super.onDisabled(context, intent)
        Log.i(TAG, "Device Administrator disabled")
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence {
        Log.i(TAG, "Device Administrator disable requested")
        return "Disabling SafeMobile Device Administrator removes its optional device policy controls."
    }

    private companion object {
        const val TAG = "SafeMobileAdmin"
    }
}
