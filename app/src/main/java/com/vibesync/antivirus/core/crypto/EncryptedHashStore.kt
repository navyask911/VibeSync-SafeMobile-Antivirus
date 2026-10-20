package com.vibesync.antivirus.core.crypto
import android.content.Context
import android.util.Base64
import com.google.crypto.tink.DeterministicAead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.daead.DeterministicAeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.nio.charset.StandardCharsets

/** Deterministic AES-SIV protects indexed hashes at rest; the Tink keyset is Keystore-wrapped. */
class EncryptedHashStore(context: Context) {
 private val primitive: DeterministicAead
 init {
  DeterministicAeadConfig.register()
  val handle = AndroidKeysetManager.Builder()
   .withKeyTemplate(KeyTemplates.get("AES256_SIV"))
   .withSharedPref(context.applicationContext, "safe_mobile_tink_keyset", "safe_mobile_crypto")
   .withMasterKeyUri("android-keystore://vibesync_safe_mobile_master_key")
   .build()
   .keysetHandle
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

 /** Encrypt definition metadata with field-specific associated data. */
 fun protectMetadata(value: String, purpose: String): String {
  require(purpose == "family" || purpose == "level") { "Unsupported definition metadata field." }
  require(value.length <= 512) { "Definition metadata is too long." }
  val encrypted=primitive.encryptDeterministically(value.toByteArray(StandardCharsets.UTF_8), metadataAad(purpose))
  return Base64.encodeToString(encrypted, Base64.NO_WRAP)
 }

 fun revealMetadata(value: String, purpose: String): String {
  require(purpose == "family" || purpose == "level") { "Unsupported definition metadata field." }
  return String(
   primitive.decryptDeterministically(Base64.decode(value, Base64.NO_WRAP), metadataAad(purpose)),
   StandardCharsets.UTF_8
  )
 }

 private fun metadataAad(purpose: String) =
  ("vibesync.safe.mobile.metadata." + purpose + ".v1").toByteArray(StandardCharsets.UTF_8)

 companion object { private val AAD = "vibesync.safe.mobile.hash.v1".toByteArray(StandardCharsets.UTF_8) }
}
