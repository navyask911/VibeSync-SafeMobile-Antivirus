package com.vibesync.antivirus.core.billing

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest

/**
 * Encrypted, device-bound entitlement cache for offline Pro gating.
 * Active subscriptions can be rehydrated from Google Play; legacy consumed INAPP grants
 * remain local-only because Google Play no longer returns consumed one-time purchases.
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

    fun expiresAt(): Long = synchronized(lock) {
        if (checkProStatusForThisDevice()) preferences.getLong(KEY_EXPIRY, 0) else 0L
    }

    /**
     * Store the subscription purchase timestamp plus its annual term and a one-day
     * local buffer. Re-reading the same purchase is idempotent. A longer legacy
     * local entitlement is never shortened during migration.
     */
    fun grantSubscription(
        purchaseToken: String,
        purchaseTimeMs: Long,
        nowMs: Long = System.currentTimeMillis()
    ): Boolean = synchronized(lock) {
        if (purchaseToken.isBlank() || purchaseTimeMs <= 0L) return@synchronized false
        val fingerprint = DeviceUtils.fingerprint(context) ?: return@synchronized false
        runCatching {
            val duration = Math.addExact(MILLIS_PER_YEAR, GOOGLE_GRACE_BUFFER_MS)
            val subscriptionExpiry = Math.addExact(purchaseTimeMs, duration)
            val oldExpiry = if (preferences.getString(KEY_FINGERPRINT, null) == fingerprint) {
                preferences.getLong(KEY_EXPIRY, 0L)
            } else {
                0L
            }
            preferences.edit()
                .putString(KEY_FINGERPRINT, fingerprint)
                .putLong(KEY_EXPIRY, maxOf(oldExpiry, subscriptionExpiry))
                .putLong(KEY_LAST_SEEN, nowMs)
                .commit()
        }.getOrDefault(false)
    }

    /**
     * Migration-only grant for the previous consumable INAPP product.
     * Token digest prevents duplicate callbacks from extending the legacy grant twice.
     */
    fun grant(
        purchaseToken: String,
        quantityFromPlay: Int,
        nowMs: Long = System.currentTimeMillis()
    ): Boolean = synchronized(lock) {
        if (purchaseToken.isBlank() || quantityFromPlay <= 0) return@synchronized false
        val fingerprint = DeviceUtils.fingerprint(context) ?: return@synchronized false
        runCatching {
            val tokenHash = MessageDigest.getInstance("SHA-256")
                .digest(purchaseToken.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            val redeemed = preferences.getStringSet(KEY_REDEEMED, emptySet())?.toSet().orEmpty()
            if (tokenHash in redeemed) return@synchronized true
            val oldExpiry = if (preferences.getString(KEY_FINGERPRINT, null) == fingerprint) {
                preferences.getLong(KEY_EXPIRY, 0)
            } else {
                0L
            }
            val base = maxOf(oldExpiry, nowMs)
            val duration = Math.multiplyExact(quantityFromPlay.toLong(), MILLIS_PER_YEAR)
            if (base > Long.MAX_VALUE - duration) return@synchronized false
            preferences.edit()
                .putString(KEY_FINGERPRINT, fingerprint)
                .putLong(KEY_EXPIRY, base + duration)
                .putLong(KEY_LAST_SEEN, nowMs)
                .putStringSet(KEY_REDEEMED, redeemed + tokenHash)
                .commit()
        }.getOrDefault(false)
    }

    companion object {
        const val MAX_YEARS = 10 // Legacy price-estimate/test compatibility; new subscriptions have quantity one.
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
