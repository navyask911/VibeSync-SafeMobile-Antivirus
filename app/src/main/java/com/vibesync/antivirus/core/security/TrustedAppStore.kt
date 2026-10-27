package com.vibesync.antivirus.core.security

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first
import java.util.Locale

private val Context.safeMobileTrustedAppStore by preferencesDataStore(name = "trusted_third_party_apks")

/**
 * User opt-out for *heuristic* prompts on exactly the same APK bytes only.
 * Never masks a verified malware hash from signed or local threat definitions.
 * Stores only package identifier + SHA-256, locally in app-private preferences.
 */
class TrustedAppStore(context: Context) {
 private val store = context.applicationContext.safeMobileTrustedAppStore
 private val key = stringSetPreferencesKey("approved_apk_hashes")
 private fun id(packageName: String, sha256: String): String? {
  val name = packageName.trim()
  val hash = sha256.trim().lowercase(Locale.ROOT)
  if (!name.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))) return null
  if (!hash.matches(Regex("[0-9a-f]{64}"))) return null
  return name + ":" + hash
 }
 suspend fun isTrusted(packageName: String, sha256: String): Boolean =
  id(packageName, sha256)?.let { it in (store.data.first()[key] ?: emptySet()) } ?: false

 suspend fun trust(packageName: String, sha256: String): Boolean {
  val target = id(packageName,sha256) ?: return false
  store.edit { preferences ->
   // Bounded to prevent unbounded user-controlled data growth.
   preferences[key] = ((preferences[key] ?: emptySet()) + target).toList().takeLast(500).toSet()
  }
  return true
 }
 suspend fun untrust(packageName: String, sha256: String) {
  val target = id(packageName, sha256) ?: return
  store.edit { prefs -> prefs[key] = (prefs[key] ?: emptySet()) - target }
 }
}
