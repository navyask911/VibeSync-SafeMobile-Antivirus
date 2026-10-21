package com.vibesync.antivirus.core.engine

import android.content.Context
import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import org.json.JSONObject
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

/** Loads a Bloom filter only after validating its bundled manifest and SHA-256. */
class BloomFilterScanner(context: Context) {
    private val app = context.applicationContext
    private val funnel = Funnels.stringFunnel(StandardCharsets.UTF_8)
    private val loaded: LoadResult by lazy(LazyThreadSafetyMode.SYNCHRONIZED) { loadVerifiedFilter() }
    private data class LoadResult(val filter: BloomFilter<CharSequence>?, val reason: String)

    /** true means possible match, false means no match, null means filter unavailable. */
    fun mightContainHash(hash: String?): Boolean? {
        val value = hash?.trim()?.lowercase(Locale.ROOT) ?: return false
        if (!SHA256.matches(value) && !SHA1.matches(value) && !MD5.matches(value)) return false
        return loaded.filter?.mightContain(value)
    }
    val isAvailable: Boolean get() = loaded.filter != null
    val availabilityReason: String get() = loaded.reason

    private fun loadVerifiedFilter(): LoadResult = try {
        val manifest = app.assets.open(MANIFEST_ASSET).use { input -> JSONObject(input.bufferedReader(Charsets.UTF_8).readText()) }
        val filename = manifest.optString("bloom_file", "")
        val expected = manifest.optString("sha256", "").lowercase(Locale.ROOT)
        val version = manifest.optInt("version", 0)
        val count = manifest.optLong("entry_count", 0L)
        if (filename != ASSET_NAME || version < 1 || count < 1 || !SHA256.matches(expected))
            return LoadResult(null, "Bloom filter manifest is incomplete or invalid.")
        val actual = app.assets.open(filename).use { it.sha256Hex() }
        if (!MessageDigest.isEqual(expected.toByteArray(StandardCharsets.US_ASCII), actual.toByteArray(StandardCharsets.US_ASCII)))
            return LoadResult(null, "Bloom filter SHA-256 does not match its manifest.")
        val filter = app.assets.open(filename).use { BloomFilter.readFrom(it, funnel) }
        LoadResult(filter, "Verified manifest and SHA-256; declared entries=" + count + ".")
    } catch (_: Exception) {
        LoadResult(null, "Bloom filter unavailable: asset or manifest is missing, invalid, or unreadable.")
    }

    private fun InputStream.sha256Hex(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        while (true) {
            val n = read(buffer)
            if (n < 0) break
            if (n > 0) digest.update(buffer, 0, n)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }
    companion object {
        const val ASSET_NAME = "hypatia_bloom.db"
        const val MANIFEST_ASSET = "manifest.json"
        private val SHA256 = Regex("^[a-f0-9]{64}$")
        private val SHA1 = Regex("^[a-f0-9]{40}$")
        private val MD5 = Regex("^[a-f0-9]{32}$")
    }
}
