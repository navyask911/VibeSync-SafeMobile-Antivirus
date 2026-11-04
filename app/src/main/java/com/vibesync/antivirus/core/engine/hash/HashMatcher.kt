package com.vibesync.antivirus.core.engine.hash

import com.google.common.hash.BloomFilter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale

data class HashDetectionResult(
    val isThreat: Boolean,
    val malwareName: String?
)

class HashMatcher {

    /**
     * Convenience entry point for callers that do not already have file digests.
     * The repository scanner uses matchDigests() with its existing three-digest
     * single-pass HashCalculator to avoid reading APK files a second time.
     */
    suspend fun scanFile(
        file: File,
        hashes: List<String>,
        bloomFilter: BloomFilter<String>
    ): HashDetectionResult = withContext(Dispatchers.IO) {
        val (md5, sha256) = FileHasher.calculateHashes(file)
        matchDigests(md5, sha256, hashes.toHashSet(), bloomFilter)
    }

    /**
     * Exact-verifies Bloom-filter candidates. EICAR is independently checked
     * against its pinned SHA-256 so detection survives an absent/corrupt asset
     * or a mistakenly unpopulated Bloom filter.
     */
    fun matchDigests(
        md5: String,
        sha256: String,
        hashes: Collection<String>,
        bloomFilter: BloomFilter<String>
    ): HashDetectionResult {
        val normalizedMd5 = md5.lowercase(Locale.ROOT)
        val normalizedSha256 = sha256.lowercase(Locale.ROOT)

        if (normalizedSha256 == EICAR_SHA256) {
            return HashDetectionResult(true, EICAR_MALWARE_NAME)
        }

        val exactHashes = if (hashes is Set<String>) hashes else hashes.toHashSet()
        val sha256Match = bloomFilter.mightContain(normalizedSha256) &&
            normalizedSha256 in exactHashes
        val md5Match = bloomFilter.mightContain(normalizedMd5) &&
            normalizedMd5 in exactHashes

        return if (sha256Match || md5Match) {
            HashDetectionResult(true, GENERIC_MALWARE_NAME)
        } else {
            HashDetectionResult(false, null)
        }
    }

    companion object {
        const val EICAR_SHA256 =
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

        const val EICAR_MALWARE_NAME = "EICAR-Test-File"
        private const val GENERIC_MALWARE_NAME = "Known hash signature"
    }
}
