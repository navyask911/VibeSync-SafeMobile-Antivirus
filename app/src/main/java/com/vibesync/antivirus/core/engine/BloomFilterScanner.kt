package com.vibesync.antivirus.core.engine
import android.content.Context
import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import java.nio.charset.StandardCharsets
import java.util.Locale
/** Optional serialized Guava filter; null means missing/invalid IOC asset. */
class BloomFilterScanner(context: Context) {
 private val app = context.applicationContext
 private val funnel = Funnels.stringFunnel(StandardCharsets.UTF_8)
 private val filter: BloomFilter<CharSequence>? by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
  runCatching { app.assets.open(ASSET_NAME).use { BloomFilter.readFrom(it, funnel) } }.getOrNull()
 }
 /** true means possible match, false means no possible match, null means filter unavailable. */
 fun mightContainHash(hash: String?): Boolean? {
  val value = hash?.trim()?.lowercase(Locale.ROOT) ?: return false
  if (!SHA256.matches(value) && !SHA1.matches(value) && !MD5.matches(value)) return false
  return filter?.mightContain(value)
 }
 val isAvailable: Boolean get() = filter != null
 companion object {
  const val ASSET_NAME = "hypatia-iocs.bloom"
  private val SHA256 = Regex("^[a-f0-9]{64}$"); private val SHA1 = Regex("^[a-f0-9]{40}$"); private val MD5 = Regex("^[a-f0-9]{32}$")
 }
}
