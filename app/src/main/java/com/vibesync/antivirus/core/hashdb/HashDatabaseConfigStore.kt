package com.vibesync.antivirus.core.hashdb

import android.content.Context
import java.net.URI

data class HashDatabaseSyncConfig(val url: String, val enabled: Boolean)

class HashDatabaseConfigStore(context: Context) {
    private val prefs = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun read(): HashDatabaseSyncConfig = HashDatabaseSyncConfig(
        url = prefs.getString(KEY_URL, "").orEmpty(),
        enabled = prefs.getBoolean(KEY_ENABLED, false)
    )

    /** Store only a user-configured HTTPS download URL. No upload URL or credentials are supported. */
    fun configure(url: String, enabled: Boolean) {
        val normalized = url.trim()
        require(normalized.length <= 2048) { "URL exceeds the supported length." }
        val parsed = URI(normalized)
        require(parsed.scheme.equals("https", ignoreCase = true) && !parsed.host.isNullOrBlank()) {
            "Only an HTTPS signature-download URL is allowed."
        }
        require(parsed.rawUserInfo == null && parsed.fragment == null) {
            "Credentials and fragments are not allowed in the update URL."
        }
        prefs.edit().putString(KEY_URL, normalized).putBoolean(KEY_ENABLED, enabled).apply()
    }

    companion object {
        private const val PREFERENCES = "safe_mobile_signed_hash_database"
        private const val KEY_URL = "download_url"
        private const val KEY_ENABLED = "download_enabled"
    }
}
