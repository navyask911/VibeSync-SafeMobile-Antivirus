package com.vibesync.antivirus.core.billing

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest

/**
 * Encrypted, device-bound local cache for prepaid subscription access.
 * It accumulates distinct prepaid top-ups while application data is present.
 */
class ProEntitlementStore(
    private val context: Context,
    private val preferencesName: String = PREFS_NAME
) {
    private val lock = Any()
    private val preferences: SharedPreferences by lazy {
        @Suppress("DEPRECATION")
        val master = MasterKey.Builder(context.applicationContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
        @Suppress("DEPRECATION")
        EncryptedSharedPreferences.create(
            context.applicationContext, preferencesName, master,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun checkProStatusForThisDevice(nowMs: Long = System.currentTimeMillis()): Boolean =
        synchronized(lock) {
            runCatching {
                val current = DeviceUtils.fingerprint(context) ?: return@synchronized false
                val saved = preferences.getString(KEY_FINGERPRINT, null)
                if (saved == null || !MessageDigest.isEqual(
                        saved.toByteArray(Charsets.US_ASCII),
                        current.toByteArray(Charsets.US_ASCII)
                    )
                ) return@synchronized false
                val expiry = preferences.getLong(KEY_EXPIRY, 0)
                val lastSeen = preferences.getLong(KEY_LAST_SEEN, 0)
                if (nowMs + CLOCK_TOLERANCE_MS < lastSeen) return@synchronized false
                if (nowMs > lastSeen) preferences.edit().putLong(KEY_LAST_SEEN, nowMs).commit()
                expiry > nowMs
            }.getOrDefault(false)
        }

    fun expiresAt(nowMs: Long = System.currentTimeMillis()): Long = synchronized(lock) {
        if (checkProStatusForThisDevice(nowMs)) preferences.getLong(KEY_EXPIRY, 0) else 0L
    }

    /** Apply one confirmed one-year prepaid purchase/top-up; each Play token grants once. */
    fun grantPrepaidSubscription(
        purchaseToken: String,
        purchaseTimeMs: Long,
        nowMs: Long = System.currentTimeMillis()
    ): Boolean = synchronized(lock) {
        if (purchaseToken.isBlank() || purchaseTimeMs <= 0L) return@synchronized false
        val fingerprint = DeviceUtils.fingerprint(context) ?: return@synchronized false
        runCatching {
            val tokenHash = MessageDigest.getInstance("SHA-256")
                .digest(purchaseToken.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            val redeemed = preferences.getStringSet(KEY_REDEEMED, emptySet())?.toSet().orEmpty()
            if (tokenHash in redeemed) return@synchronized true

            val oldExpiry = if (preferences.getString(KEY_FINGERPRINT, null) == fingerprint) {
                preferences.getLong(KEY_EXPIRY, 0L)
            } else {
                0L
            }
            val base = maxOf(oldExpiry, purchaseTimeMs)
            val duration = Math.addExact(MILLIS_PER_YEAR, GOOGLE_GRACE_BUFFER_MS)
            val newExpiry = Math.addExact(base, duration)
            preferences.edit()
                .putString(KEY_FINGERPRINT, fingerprint)
                .putLong(KEY_EXPIRY, newExpiry)
                .putLong(KEY_LAST_SEEN, nowMs)
                .putStringSet(KEY_REDEEMED, redeemed + tokenHash)
                .commit()
        }.getOrDefault(false)
    }

    /** Clear local access if Play reports an active purchase linked to another device. */
    fun clearForDeviceMismatch(): Boolean = synchronized(lock) {
        runCatching {
            preferences.edit()
                .remove(KEY_FINGERPRINT)
                .remove(KEY_EXPIRY)
                .remove(KEY_LAST_SEEN)
                .remove(KEY_REDEEMED)
                .commit()
        }.getOrDefault(false)
    }

    companion object {
        const val MILLIS_PER_YEAR = 365L * 24 * 60 * 60 * 1000
        const val GOOGLE_GRACE_BUFFER_MS = 24L * 60 * 60 * 1000
        private const val CLOCK_TOLERANCE_MS = 5L * 60 * 1000
        private const val PREFS_NAME = "safe_mobile_pro_entitlements"
        private const val KEY_FINGERPRINT = "device_sha256"
        private const val KEY_EXPIRY = "expires_at"
        private const val KEY_LAST_SEEN = "last_seen"
        private const val KEY_REDEEMED = "redeemed_purchase_sha256"
    }
}
