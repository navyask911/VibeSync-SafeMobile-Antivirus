package com.vibesync.antivirus.core.security

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class GlobalThreatIntelligenceDonorTest {
    @Test fun payloadContainsOnlyHashAnd215BinaryFeatures() {
        val hash = "a".repeat(64)
        val vector = FloatArray(215) { if (it % 2 == 0) 1f else 0f }
        val payload = JSONObject(GlobalThreatIntelligenceDonor.buildPayload(hash, vector))
        assertEquals(setOf("sha256", "features"), payload.keys().asSequence().toSet())
        assertEquals(hash, payload.getString("sha256"))
        val features = payload.getJSONArray("features")
        assertEquals(215, features.length())
        for (index in 0 until features.length()) {
            assertEquals(if (index % 2 == 0) 1 else 0, features.getInt(index))
        }
    }

    @Test fun rejectsIncorrectFeatureCount() {
        assertThrows(IllegalArgumentException::class.java) {
            GlobalThreatIntelligenceDonor.buildPayload("b".repeat(64), FloatArray(32))
        }
    }

    @Test fun rejectsNonBinaryFeatures() {
        val vector = FloatArray(215)
        vector[17] = 0.5f
        assertThrows(IllegalArgumentException::class.java) {
            GlobalThreatIntelligenceDonor.buildPayload("c".repeat(64), vector)
        }
    }
}
