package com.vibesync.antivirus.core.security

import android.app.admin.DeviceAdminReceiver
import android.content.Context
import android.content.Intent
import com.vibesync.antivirus.R

/** Consumer Device Administrator; disable-request text warns but cannot prevent deactivation. */
class AntivirusAdminReceiver : DeviceAdminReceiver() {
    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        context.getString(R.string.device_admin_disable_warning)
}
