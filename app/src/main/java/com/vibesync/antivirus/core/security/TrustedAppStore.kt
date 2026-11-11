package com.vibesync.antivirus.core.security

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first

private val Context.safeMobileTrustedAppStore by preferencesDataStore(name = "trusted_third_party_apks")

/** Explicit user override by package name, including subsequent updates. App-private, offline only. */
class TrustedAppStore(context: Context) {
 private val store = context.applicationContext.safeMobileTrustedAppStore
 private val packages = stringSetPreferencesKey("trusted_package_names")
 private val legacyHashes = stringSetPreferencesKey("approved_apk_hashes")
 private fun valid(name: String) = name.matches(Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+"))
 suspend fun isTrusted(packageName: String): Boolean {
  if (!valid(packageName)) return false
  val prefs = store.data.first()
  // Upgrade existing user choices to the requested absolute package-level trust policy.
  return packageName in prefs[packages].orEmpty() ||
   prefs[legacyHashes].orEmpty().any { it.substringBefore(':') == packageName }
 }
 suspend fun trust(packageName: String): Boolean {
  if (!valid(packageName)) return false
  store.edit { it[packages] = it[packages].orEmpty() + packageName }
  return true
 }
 suspend fun untrust(packageName: String) {
  if (!valid(packageName)) return
  store.edit {
   it[packages] = it[packages].orEmpty() - packageName
   it[legacyHashes] = it[legacyHashes].orEmpty().filterNot { entry ->
    entry.substringBefore(':') == packageName
   }.toSet()
  }
 }
}
