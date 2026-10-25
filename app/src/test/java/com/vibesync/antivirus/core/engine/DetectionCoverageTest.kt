package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionCoverageTest {
    @Test fun unshippedLayersAreExplicitlyDisabled() {
        listOf("bloom-hash-index", "yara-dex-and-assets", "tflite-permission-model",
            "offline-signer-attestation").forEach { id ->
            val layer = DetectionCoverage.status(id)
            assertNotNull("Missing coverage entry: " + id, layer)
            assertEquals(DetectionLayerState.DISABLED, layer?.state)
            assertTrue(layer?.reason.orEmpty().isNotBlank())
        }
        val feed = DetectionCoverage.status("signed-feed-manifest")
        assertEquals(DetectionLayerState.CONDITIONAL, feed?.state)
        assertTrue(feed?.reason.orEmpty().contains("public key"))
    }
    @Test fun activeHashLayerDisclosesEicarOnlyLimitation() {
        val layer = DetectionCoverage.status("local-hash-definitions")
        assertEquals(DetectionLayerState.ACTIVE_LIMITED, layer?.state)
        assertTrue(layer?.reason.orEmpty().contains("harmless EICAR test marker"))
    }
}
