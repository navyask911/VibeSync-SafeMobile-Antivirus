package com.vibesync.antivirus.core.worker

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ThreatIntelligenceStatsTest {
    private fun fixture() = JSONObject().put("total_malware_samples", 5560)
        .put("accuracy", 97.450034).put("total_downloads", 12000)
        .put("last_updated", "2026-10-31T00:30:00+05:30")
    private fun parse(json: JSONObject) = ThreatIntelligenceStats.parse(json.toString().toByteArray())

    @Test fun acceptsReleaseCountsAndFractionOrPercentAccuracy() {
        val json = fixture()
        assertEquals(5560L, parse(json)!!.totalMalwareSamples)
        assertEquals(12000L, parse(json)!!.totalDownloads)
        assertEquals(0.97450034, parse(json)!!.accuracyFraction, 0.000000001)
        assertEquals(0.9745, parse(json.put("accuracy", 0.9745))!!.accuracyFraction, 0.000000001)
        assertEquals(0.9745, parse(json.put("accuracy", "97.45%"))!!.accuracyFraction, 0.000000001)
        assertEquals(0.01, parse(json.put("accuracy", "1%"))!!.accuracyFraction, 0.000000001)
    }

    @Test fun supportsIsoDatesAndRealZeroCountsWithoutFabricatingMissingValues() {
        val json = fixture().put("total_downloads", 0).put("last_updated", "2026-10-31")
        assertEquals(0L, parse(json)!!.totalDownloads)
        for (key in listOf("total_downloads", "total_malware_samples", "accuracy", "last_updated")) {
            val missing = fixture().apply { remove(key) }
            assertNull(parse(missing))
        }
    }

    @Test fun rejectsInvalidCountsMetricsAndUnzonedOrInvalidDates() {
        for (count in listOf(-1, 2.5, true, "10", JSONObject.NULL, "9223372036854775808")) {
            assertNull(parse(fixture().put("total_malware_samples", count)))
            assertNull(parse(fixture().put("total_downloads", count)))
        }
        for (accuracy in listOf(-1, 100.1, true, "NaN%", "Infinity%", "97.45", JSONObject.NULL)) {
            assertNull(parse(fixture().put("accuracy", accuracy)))
        }
        for (date in listOf("yesterday", "2026-02-30", "2026-10-31T00:30:00", "", "x".repeat(65))) {
            assertNull(parse(fixture().put("last_updated", date)))
        }
    }

    @Test fun rejectsMalformedOversizedAndTrailingContent() {
        for (text in listOf("", "[]", "null", "{", fixture().toString() + " garbage")) {
            assertNull(ThreatIntelligenceStats.parse(text.toByteArray()))
        }
        assertNull(ThreatIntelligenceStats.parse(ByteArray(ThreatIntelligenceStats.MAX_BYTES + 1)))
    }
}
