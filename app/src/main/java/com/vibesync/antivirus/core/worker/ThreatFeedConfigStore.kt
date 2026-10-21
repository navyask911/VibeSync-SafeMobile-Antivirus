package com.vibesync.antivirus.core.worker

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

enum class ThreatFeedFormat { AUTO, JSON, CSV }
enum class ThreatFeedRequestMode { GET, POST_JSON }
/** Incremental is the safe default; snapshot replacement requires a complete, non-empty response. */
enum class ThreatFeedUpdateMode { INCREMENTAL, AUTHORITATIVE_SNAPSHOT }

data class ThreatFeedConfiguration(
    val url: String = "",
    val authKey: String = "",
    val format: ThreatFeedFormat = ThreatFeedFormat.AUTO,
    val requestMode: ThreatFeedRequestMode = ThreatFeedRequestMode.GET,
    val postJson: String = DEFAULT_POST_JSON,
    val updateMode: ThreatFeedUpdateMode = ThreatFeedUpdateMode.INCREMENTAL
) {
    companion object {
        const val DEFAULT_POST_JSON = """{"query":"get_iocs","days":7}"""
    }
}

/** Stores feed credentials encrypted with a non-exportable AES-GCM Android Keystore key. */
class ThreatFeedConfigStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun load(): ThreatFeedConfiguration = ThreatFeedConfiguration(
        url = preferences.getString(KEY_URL, "").orEmpty(),
        authKey = runCatching { decrypt(preferences.getString(KEY_AUTH, null)) }.getOrDefault(""),
        format = runCatching { ThreatFeedFormat.valueOf(preferences.getString(KEY_FORMAT, "AUTO") ?: "AUTO") }
            .getOrDefault(ThreatFeedFormat.AUTO),
        requestMode = runCatching { ThreatFeedRequestMode.valueOf(preferences.getString(KEY_MODE, "GET") ?: "GET") }
            .getOrDefault(ThreatFeedRequestMode.GET),
        postJson = preferences.getString(KEY_POST_JSON, ThreatFeedConfiguration.DEFAULT_POST_JSON)
            ?: ThreatFeedConfiguration.DEFAULT_POST_JSON,
        updateMode = runCatching {
            ThreatFeedUpdateMode.valueOf(preferences.getString(KEY_UPDATE_MODE, "INCREMENTAL") ?: "INCREMENTAL")
        }.getOrDefault(ThreatFeedUpdateMode.INCREMENTAL)
    )

    fun save(config: ThreatFeedConfiguration) {
        val url = validateHttpsUrl(config.url)
        require(config.authKey.length <= MAX_AUTH_KEY_LENGTH) { "The feed authentication key is too long." }
        if (config.requestMode == ThreatFeedRequestMode.POST_JSON) {
            require(config.postJson.length <= MAX_POST_BODY_LENGTH) { "The JSON request body is too large." }
            JSONObject(config.postJson)
        }
        val encryptedAuth = config.authKey.trim().takeIf(String::isNotEmpty)?.let(::encrypt)
        check(preferences.edit().putString(KEY_URL, url).putString(KEY_FORMAT, config.format.name)
            .putString(KEY_MODE, config.requestMode.name).putString(KEY_POST_JSON, config.postJson)
            .putString(KEY_UPDATE_MODE, config.updateMode.name)
            .putString(KEY_AUTH, encryptedAuth).commit()) { "Could not save feed configuration." }
    }

    fun clear() {
        check(preferences.edit().clear().commit()) { "Could not clear feed configuration." }
    }

    fun isConfigured(): Boolean = preferences.getString(KEY_URL, "").orEmpty().isNotBlank()

    /** Network feed access is a separate explicit consent, false on clean install. */
    fun isSyncEnabled(): Boolean = preferences.getBoolean(KEY_SYNC_ENABLED, false)

    fun setSyncEnabled(enabled: Boolean) {
        check(preferences.edit().putBoolean(KEY_SYNC_ENABLED, enabled).commit()) {
            "Could not save threat-feed network consent."
        }
    }

    private fun validateHttpsUrl(value: String): String {
        val url = value.trim()
        require(url.isNotBlank() && url.length <= MAX_URL_LENGTH) { "Enter a feed URL." }
        val uri = runCatching { URI(url) }.getOrElse { throw IllegalArgumentException("The feed URL is invalid.") }
        require(uri.scheme.equals("https", ignoreCase = true) && !uri.host.isNullOrBlank()) {
            "Threat feeds must use HTTPS."
        }
        require(uri.userInfo == null) { "Do not put credentials in the URL; use the encrypted Auth-Key field." }
        val queryNames = uri.rawQuery.orEmpty().split('&').map { it.substringBefore('=').lowercase() }
        require(queryNames.none { it.contains("token") || it.contains("apikey") || it.contains("authkey") || it == "key" }) {
            "Do not put an API key or token in the URL. Use the encrypted Auth-Key field instead."
        }
        return uri.toASCIIString()
    }

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val encrypted = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.encodeToString(ByteBuffer.allocate(cipher.iv.size + encrypted.size)
            .put(cipher.iv).put(encrypted).array(), Base64.NO_WRAP)
    }

    private fun decrypt(value: String?): String {
        if (value.isNullOrBlank()) return ""
        val packed = Base64.decode(value, Base64.NO_WRAP)
        require(packed.size > IV_LENGTH) { "Stored feed credential is invalid." }
        val iv = packed.copyOfRange(0, IV_LENGTH)
        val encrypted = packed.copyOfRange(IV_LENGTH, packed.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return String(cipher.doFinal(encrypted), StandardCharsets.UTF_8)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(
            KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true).build())
        return generator.generateKey()
    }

    companion object {
        private const val PREFS_NAME = "safe_mobile_threat_feed"
        private const val KEY_URL = "feed_url"
        private const val KEY_SYNC_ENABLED = "network_sync_consent"
        private const val KEY_AUTH = "encrypted_auth_key"
        private const val KEY_FORMAT = "format"
        private const val KEY_MODE = "request_mode"
        private const val KEY_POST_JSON = "post_json"
        private const val KEY_UPDATE_MODE = "update_mode"
        private const val KEY_ALIAS = "safemobile_threat_feed_auth_v1"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12
        private const val MAX_URL_LENGTH = 2048
        private const val MAX_AUTH_KEY_LENGTH = 4096
        private const val MAX_POST_BODY_LENGTH = 16 * 1024
    }
}
