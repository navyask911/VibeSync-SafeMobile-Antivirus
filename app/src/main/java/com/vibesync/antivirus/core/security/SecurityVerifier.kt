package com.vibesync.antivirus.core.security

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.android.gms.tasks.Task
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.vibesync.antivirus.BuildConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.SecureRandom
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.math.abs

enum class SecurityVerificationStatus {
    NOT_CHECKED,
    REQUESTING_TOKEN,
    AWAITING_SERVER_VERDICT,
    VERIFIED,
    NOT_VERIFIED,
    ERROR,
    LOCAL_BASELINE_PASSED,
    LOCAL_BASELINE_FAILED
}

data class SecurityVerificationState(
    val status: SecurityVerificationStatus = SecurityVerificationStatus.NOT_CHECKED,
    /** A decoded Google Play verdict; local checks never populate this field. */
    val meetsDeviceIntegrity: Boolean? = null,
    /** Device-local fallback only; this is not Google Play Integrity attestation. */
    val localBaselineTrusted: Boolean? = null,
    val localBaselineReasons: List<String> = emptyList()
) {
    val integrityCheckPassed: Boolean? get() = meetsDeviceIntegrity ?: localBaselineTrusted
}

/**
 * Requests the Play Integrity token on app launch.
 *
 * Play Integrity tokens are encrypted. They are deliberately never interpreted on-device:
 * a configured HTTPS backend must call Google's decodeIntegrityToken endpoint, validate the
 * nonce and package name, then return the decoded Google response as tokenPayloadExternal.
 *
 * Set PLAY_INTEGRITY_VERIFICATION_URL in the build environment to enable server-decoded
 * Google Play verdicts. When the URL is missing or validated internet is unavailable, the
 * verifier reports a separate conservative local baseline; it never labels that as attestation.
 */
class SecurityVerifier(context: Context) {
    private val app = context.applicationContext
    private val manager: IntegrityManager by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        IntegrityManagerFactory.create(app)
    }

    private val mutableState = MutableStateFlow(loadCachedState())
    val state = mutableState.asStateFlow()

    suspend fun requestIntegrityTokenAndVerify() {
        val endpoint = BuildConfig.PLAY_INTEGRITY_VERIFICATION_URL.trim()
        val online = withContext(Dispatchers.IO) { LocalBaselineTrust.hasValidatedInternet(app) }
        if (LocalBaselineTrust.shouldUseLocalBaseline(endpoint, online)) {
            applyLocalBaselineFallback(
                reason = if (endpoint.isBlank()) "No remote verification endpoint is configured."
                    else "No validated internet connection is available."
            )
            return
        }

        mutableState.value = SecurityVerificationState(status = SecurityVerificationStatus.REQUESTING_TOKEN)
        try {
            val nonce = createNonce()
            val token = manager.requestIntegrityToken(
                IntegrityTokenRequest.builder().setNonce(nonce).build()
            ).awaitTask().token()
            val meetsDeviceIntegrity = withContext(Dispatchers.IO) {
                decodeAtTrustedBackend(endpoint, token, nonce)
            }
            app.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_VERDICT, meetsDeviceIntegrity)
                .putLong(KEY_VERIFIED_AT, System.currentTimeMillis())
                .apply()
            mutableState.value = SecurityVerificationState(
                status = if (meetsDeviceIntegrity) SecurityVerificationStatus.VERIFIED
                    else SecurityVerificationStatus.NOT_VERIFIED,
                meetsDeviceIntegrity = meetsDeviceIntegrity
            )
        } catch (error: Exception) {
            val stillOffline = withContext(Dispatchers.IO) {
                !LocalBaselineTrust.hasValidatedInternet(app)
            }
            if (stillOffline) {
                applyLocalBaselineFallback("Connectivity was lost before remote verification completed.")
            } else {
                mutableState.value = SecurityVerificationState(status = SecurityVerificationStatus.ERROR)
                Log.w(TAG, "Play Integrity verification did not complete.", error)
            }
        }
    }

    private suspend fun applyLocalBaselineFallback(reason: String) {
        val report = withContext(Dispatchers.IO) { LocalBaselineTrust.evaluate(app) }
        mutableState.value = SecurityVerificationState(
            status = if (report.trusted) SecurityVerificationStatus.LOCAL_BASELINE_PASSED
                else SecurityVerificationStatus.LOCAL_BASELINE_FAILED,
            meetsDeviceIntegrity = null,
            localBaselineTrusted = report.trusted,
            localBaselineReasons = report.reasons
        )
        Log.i(TAG, "Using local baseline fallback: $reason Trusted=${report.trusted}.")
    }

    private fun createNonce(): String {
        val bytes = ByteArray(NONCE_BYTES)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    /**
     * Backend request contract:
     * POST {"integrityToken":"…","nonce":"…","packageName":"…"}
     * Response is Google's successful decodeIntegrityToken JSON with tokenPayloadExternal.
     */
    private fun decodeAtTrustedBackend(endpoint: String, token: String, nonce: String): Boolean {
        val url = URL(endpoint)
        require(url.protocol.equals("https", ignoreCase = true)) {
            "Play Integrity verification endpoint must use HTTPS."
        }
        val connection = (url.openConnection() as? HttpURLConnection)
            ?: throw IOException("Unsupported Play Integrity verification endpoint.")
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.instanceFollowRedirects = false
            connection.doOutput = true
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/json; charset=utf-8")
            val requestBody = JSONObject()
                .put("integrityToken", token)
                .put("nonce", nonce)
                .put("packageName", app.packageName)
                .toString()
            connection.outputStream.use { output ->
                output.write(requestBody.toByteArray(Charsets.UTF_8))
            }

            val statusCode = connection.responseCode
            val responseStream = if (statusCode in 200..299) connection.inputStream
                else connection.errorStream
            val responseBody = responseStream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            if (statusCode !in 200..299) {
                throw IOException("Integrity verification backend returned HTTP $statusCode.")
            }

            val root = JSONObject(responseBody)
            val payload = root.getJSONObject("tokenPayloadExternal")
            val requestDetails = payload.getJSONObject("requestDetails")
            require(requestDetails.optString("requestPackageName") == app.packageName) {
                "Decoded Play Integrity package name did not match this app."
            }
            require(requestDetails.optString("nonce") == nonce) {
                "Decoded Play Integrity nonce did not match this request."
            }
            val timestamp = requestDetails.optLong("timestampMillis", 0L)
            require(timestamp > 0L && abs(System.currentTimeMillis() - timestamp) <= MAX_VERDICT_AGE_MS) {
                "Decoded Play Integrity verdict is missing or stale."
            }
            val verdicts = payload.getJSONObject("deviceIntegrity")
                .optJSONArray("deviceRecognitionVerdict")
            return (0 until (verdicts?.length() ?: 0)).any { index ->
                verdicts?.optString(index) == MEETS_DEVICE_INTEGRITY
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun loadCachedState(): SecurityVerificationState {
        val verdict = readStoredVerdict(app) ?: return SecurityVerificationState()
        val status = if (verdict) SecurityVerificationStatus.VERIFIED
            else SecurityVerificationStatus.NOT_VERIFIED
        return SecurityVerificationState(status, verdict)
    }

    companion object {
        private const val TAG = "SafeMobileIntegrity"
        private const val PREFS = "safe_mobile_play_integrity"
        private const val KEY_VERDICT = "meets_device_integrity"
        private const val KEY_VERIFIED_AT = "verified_at"
        private const val NONCE_BYTES = 32
        private const val CONNECT_TIMEOUT_MS = 15_000
        private const val READ_TIMEOUT_MS = 20_000
        private const val MAX_VERDICT_AGE_MS = 2 * 60 * 1000L
        private const val MEETS_DEVICE_INTEGRITY = "MEETS_DEVICE_INTEGRITY"
        const val VERDICT_FRESHNESS_MS = 6L * 60 * 60 * 1000

        /** Returns only a recent verdict written after a successful HTTPS backend decode. */
        fun readStoredVerdict(context: Context): Boolean? {
            val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            if (!prefs.contains(KEY_VERDICT)) return null
            val verifiedAt = prefs.getLong(KEY_VERIFIED_AT, 0L)
            val age = System.currentTimeMillis() - verifiedAt
            if (verifiedAt <= 0L || age !in 0..VERDICT_FRESHNESS_MS) return null
            return prefs.getBoolean(KEY_VERDICT, false)
        }
    }
}

private suspend fun <T> Task<T>.awaitTask(): T = suspendCancellableCoroutine { continuation ->
    addOnSuccessListener { value ->
        if (continuation.isActive) continuation.resume(value)
    }
    addOnFailureListener { error ->
        if (continuation.isActive) continuation.resumeWithException(error)
    }
}
