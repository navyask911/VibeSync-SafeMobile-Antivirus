package com.vibesync.antivirus.core.worker

import java.time.LocalDate
import java.time.OffsetDateTime
import org.json.JSONObject
import org.json.JSONTokener

/** Release-reported training statistics, never a device scan result or an activation gate. */
internal data class ThreatIntelligenceStats(
    val totalMalwareSamples: Long,
    val accuracyFraction: Double,
    val totalDownloads: Long,
    val lastUpdated: String
) {
    companion object {
        const val FILE_NAME = "stats.json"
        const val MAX_BYTES = 16 * 1024

        /** Reject incomplete/corrupt input rather than presenting invented zero counts. */
        fun parse(bytes: ByteArray): ThreatIntelligenceStats? = runCatching {
            require(bytes.isNotEmpty() && bytes.size <= MAX_BYTES)
            val tokens = JSONTokener(bytes.toString(Charsets.UTF_8))
            val json = tokens.nextValue() as? JSONObject ?: error("Statistics must be an object")
            require(tokens.nextClean() == '\u0000')
            fun count(key: String): Long {
                val number = json.get(key) as? Number ?: error("Count is not numeric")
                return number.toString().toBigDecimal().longValueExact().also { require(it >= 0) }
            }
            val samples = count("total_malware_samples")
            val downloads = count("total_downloads")
            val rawAccuracy = json.get("accuracy")
            val explicitlyPercent = rawAccuracy is String && rawAccuracy.trim().endsWith('%')
            val accuracy = when (rawAccuracy) {
                is Number -> rawAccuracy.toDouble()
                is String -> if (explicitlyPercent) rawAccuracy.trim().dropLast(1).trim().toDouble()
                    else error("Accuracy string needs a percent sign")
                else -> error("Accuracy is not numeric")
            }
            require(accuracy.isFinite() && accuracy in 0.0..100.0)
            val fraction = if (explicitlyPercent || accuracy > 1.0) accuracy / 100.0 else accuracy
            val updated = json.get("last_updated") as? String ?: error("Update date is not text")
            require(updated.length in 1..64)
            // Accept an ISO date or a timestamp with an explicit offset; never guess a timezone.
            require(runCatching { OffsetDateTime.parse(updated) }.isSuccess ||
                runCatching { LocalDate.parse(updated) }.isSuccess)
            ThreatIntelligenceStats(samples, fraction, downloads, updated)
        }.getOrNull()
    }
}
