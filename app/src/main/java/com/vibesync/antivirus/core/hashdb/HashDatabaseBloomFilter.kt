package com.vibesync.antivirus.core.hashdb

import java.nio.ByteBuffer
import java.security.MessageDigest
import kotlin.math.ceil
import kotlin.math.ln
import kotlin.math.max

/**
 * Compact O(1)-average pre-filter. It may have false positives; every positive is verified by
 * an exact indexed Room/SQLite lookup before it becomes a detection.
 */
class HashDatabaseBloomFilter private constructor(
    private val bitCount: Int,
    private val hashCount: Int,
    private val bits: ByteArray
) {
    fun add(value: String) {
        forEachBit(value) { bit ->
            val index = bit ushr 3
            bits[index] = (bits[index].toInt() or (1 shl (bit and 7))).toByte()
        }
    }

    fun mightContain(value: String): Boolean {
        forEachBit(value) { bit ->
            val index = bit ushr 3
            if ((bits[index].toInt() and (1 shl (bit and 7))) == 0) return false
        }
        return true
    }

    private inline fun forEachBit(value: String, action: (Int) -> Unit) {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
        val buffer = ByteBuffer.wrap(digest)
        val first = buffer.long
        var second = buffer.long
        if (second == 0L) second = -7046029254386353131L
        var index = 0
        while (index < hashCount) {
            action(Math.floorMod(first + index.toLong() * second, bitCount.toLong()).toInt())
            index++
        }
    }

    companion object {
        private const val FALSE_POSITIVE_RATE = 0.005
        private const val MAX_BITS = 32_000_000
        private const val MAX_ITEMS = 200_000

        fun create(expectedItems: Int): HashDatabaseBloomFilter {
            require(expectedItems in 1..MAX_ITEMS) { "Invalid Bloom filter item count." }
            val idealBits = ceil(-expectedItems * ln(FALSE_POSITIVE_RATE) / (ln(2.0) * ln(2.0)))
                .toLong().coerceAtMost(MAX_BITS.toLong()).toInt()
            val bits = max(64, idealBits)
            val hashes = max(1, (bits.toDouble() / expectedItems * ln(2.0)).toInt()).coerceAtMost(12)
            return HashDatabaseBloomFilter(bits, hashes, ByteArray((bits + 7) / 8))
        }

        fun fromRecords(records: Collection<HashDatabaseRecord>): HashDatabaseBloomFilter {
            val filter = create(records.size)
            records.forEach { filter.add(it.bloomKey) }
            return filter
        }
    }
}
