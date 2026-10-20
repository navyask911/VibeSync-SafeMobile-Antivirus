package com.vibesync.antivirus.core.crypto
import android.content.Context
import android.util.Base64
import com.google.crypto.tink.DeterministicAead
import com.google.crypto.tink.aead.AesSivKeyManager
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.nio.charset.StandardCharsets

/** Deterministic AES-SIV protects indexed hashes at rest; the Tink keyset is Keystore-wrapped. */
class EncryptedHashStore(context: Context) {
 private val primitive: DeterministicAead
 init {
  AesSivKeyManager.register(true)
  val handle = AndroidKeysetManager.Builder()
   .withSharedPref(context.applicationContext, "safe_mobile_tink_keyset", "safe_mobile_crypto")
   .withKeyTemplate(AesSivKeyManager.aes256SivTemplate())
   .withMasterKeyUri("android-keystore://vibesync_safe_mobile_master_key")
   .build().keysetHandle
  primitive = handle.getPrimitive(DeterministicAead::class.java)
 }
 fun protectHash(hash: String): String {
  require(hash.matches(Regex("(?i)^[a-f0-9]{64}$"))) { "Expected SHA-256 hex" }
  val encrypted = primitive.encryptDeterministically(hash.lowercase().toByteArray(StandardCharsets.UTF_8), AAD)
  return Base64.encodeToString(encrypted, Base64.NO_WRAP)
 }
 fun revealHash(value: String): String = String(
  primitive.decryptDeterministically(Base64.decode(value, Base64.NO_WRAP), AAD), StandardCharsets.UTF_8
 )
 companion object { private val AAD = "vibesync.safe.mobile.hash.v1".toByteArray(StandardCharsets.UTF_8) }
}
