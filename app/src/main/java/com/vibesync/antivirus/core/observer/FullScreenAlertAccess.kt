package com.vibesync.antivirus.core.observer

import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log

/** Full-screen access is optional and independent of the user's siren/notification opt-in. */
object FullScreenAlertAccess {
    fun isGranted(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < 34) return true
        return runCatching {
            context.getSystemService(NotificationManager::class.java)?.canUseFullScreenIntent() == true
        }.onFailure { Log.w("SafeMobileSecurityAlert", "Unable to read full-screen access", it) }.getOrDefault(false)
    }

    fun settingsIntent(context: Context): Intent? = if (Build.VERSION.SDK_INT >= 34) {
        Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
            Uri.fromParts("package", context.packageName, null))
    } else null
}
