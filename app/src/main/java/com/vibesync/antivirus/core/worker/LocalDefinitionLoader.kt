package com.vibesync.antivirus.core.worker
import android.content.Context
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.data.local.ThreatDao
import com.vibesync.antivirus.data.local.ThreatSignature
import org.json.JSONObject
import java.io.IOException

/**
 * Imports a bundled offline JSON set once, only if the local Room definition table is empty.
 * The starter asset deliberately contains no fabricated malware hashes; replace it with a curated,
 * licensed dataset after validating its provenance and hashes before distributing a production build.
 */
class LocalDefinitionLoader(
 private val context: Context,
 private val dao: ThreatDao,
 private val hashStore: EncryptedHashStore
) {
 suspend fun importBundledIfEmpty(): Int {
  if (dao.countSignatures() > 0) return 0
  val json = try {
   context.assets.open("offline-threat-definitions.json").bufferedReader(Charsets.UTF_8).use { it.readText() }
  } catch (_: IOException) { return 0 }
  val array = JSONObject(json).optJSONArray("definitions") ?: return 0
  val rows = mutableListOf<ThreatSignature>()
  for (index in 0 until array.length()) {
   val row = array.getJSONObject(index)
   val hash = row.optString("sha256").lowercase()
   if (!hash.matches(Regex("^[a-f0-9]{64}$"))) continue
   rows += ThreatSignature(
    hash = hashStore.protectHash(hash),
    malwareFamily = row.optString("malware_family", "Unknown").take(120),
    threatLevel = row.optString("threat_level", "unknown").take(32),
    dateAdded = row.optLong("date_added", System.currentTimeMillis())
   )
  }
  if (rows.isNotEmpty()) dao.upsertSignatures(rows)
  return rows.size
 }
}
