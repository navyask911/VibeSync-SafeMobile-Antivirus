package com.vibesync.antivirus.core.billing

import android.content.Context
import android.provider.Settings
import java.security.MessageDigest

/** App-scoped, device-local equality check. Never upload or log the Android ID. */
object DeviceUtils {
    fun fingerprint(context: Context): String? {
        val id = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?.takeUnless { it.isBlank() || it == "9774d56d682e549c" } ?: return null
        val payload = "SafeMobile.Pro.Device.v1\u0000${context.packageName}\u0000$id"
            .toByteArray(Charsets.UTF_8)
        return MessageDigest.getInstance("SHA-256").digest(payload)
            .joinToString("") { "%02x".format(it) }
    }
}
