package com.vibesync.antivirus.core.engine.hash

import com.google.common.hash.BloomFilter
import com.google.common.hash.Funnels
import java.util.Locale

class BloomFilterBuilder {

    fun buildBloomFilter(hashes: List<String>): BloomFilter<String> {
        // Guava rejects zero expected insertions. Callers include the EICAR
        // fallback, but keep this builder safe for an empty standalone input.
        val expectedInsertions = hashes.size.coerceAtLeast(1).toLong()
        val filter = BloomFilter.create<String>(
            Funnels.stringFunnel(Charsets.UTF_8),
            expectedInsertions,
            FALSE_POSITIVE_PROBABILITY
        )

        hashes.asSequence()
            .map { it.trim().lowercase(Locale.ROOT) }
            .filter(String::isNotEmpty)
            .distinct()
            .forEach(filter::put)

        return filter
    }

    private companion object {
        const val FALSE_POSITIVE_PROBABILITY = 0.0001
    }
}
