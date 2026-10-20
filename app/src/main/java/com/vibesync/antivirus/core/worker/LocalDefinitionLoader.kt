package com.vibesync.antivirus.core.worker
import android.content.Context
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.data.local.ThreatDao
import com.vibesync.antivirus.data.local.ThreatSignature
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import kotlinx.coroutines.sync.Mutex

/** Imports local JSON signatures; the starter asset has no fabricated malware hashes. */
class LocalDefinitionLoader(private val context: Context, private val dao: ThreatDao, private val hashStore: EncryptedHashStore) {
 private val importMutex = Mutex()

 suspend fun importBundledIfEmpty(): Int {
  importMutex.lock()
  try {
   if (dao.countSignatures() > 0) return 0
   val stream = try { context.assets.open("offline-threat-definitions.json") } catch (_: IOException) { return 0 }
   return parseAndImport(stream)
  } finally {
   importMutex.unlock()
  }
 }

 /** Schema: {"schema_version":1,"definitions":[{"sha256":"64 hex chars","malware_family":"family","threat_level":"high","date_added":123}]}. */
 suspend fun importFromStream(stream: InputStream): Int {
  importMutex.lock()
  try {
   return parseAndImport(stream)
  } finally {
   importMutex.unlock()
  }
 }

 private suspend fun parseAndImport(stream: InputStream): Int {
  val payload = stream.use { input ->
   val output = ByteArrayOutputStream()
   val buffer = ByteArray(8192)
   var total = 0
   while (true) {
    val count = input.read(buffer)
    if (count < 0) break
    total += count
    require(total <= MAX_IMPORT_BYTES) { "Definition file exceeds the supported size limit." }
    output.write(buffer, 0, count)
   }
   output.toString(Charsets.UTF_8.name())
  }
  val definitions = JSONObject(payload).optJSONArray("definitions") ?: throw IllegalArgumentException("Expected a definitions array.")
  require(definitions.length() <= MAX_DEFINITIONS) { "Definition count exceeds the supported limit." }
  val rows = mutableListOf<ThreatSignature>()
  for (index in 0 until definitions.length()) {
   val row = definitions.optJSONObject(index) ?: continue
   val hash = row.optString("sha256").lowercase()
   if (!hash.matches(Regex("^[a-f0-9]{64}$"))) continue
   rows += ThreatSignature(hash=hashStore.protectHash(hash), malwareFamily=hashStore.protectMetadata(row.optString("malware_family","Unknown").take(120), "family"),
    threatLevel=hashStore.protectMetadata(row.optString("threat_level","unknown").take(32), "level"), dateAdded=row.optLong("date_added",System.currentTimeMillis()))
  }
  rows.chunked(BATCH_SIZE).forEach { dao.upsertSignatures(it) }
  return rows.size
 }
 companion object { private const val MAX_IMPORT_BYTES=8*1024*1024; private const val MAX_DEFINITIONS=100_000; private const val BATCH_SIZE=500 }
}
