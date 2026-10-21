package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DetectionCoverageTest {
    @Test fun unshippedLayersAreExplicitlyDisabled() {
        listOf("bloom-hash-index", "yara-dex-and-assets", "tflite-permission-model",
            "offline-signer-attestation", "signed-feed-manifest").forEach { id ->
            val layer = DetectionCoverage.status(id)
            assertNotNull("Missing coverage entry: " + id, layer)
            assertEquals(DetectionLayerState.DISABLED, layer?.state)
            assertTrue(layer?.reason.orEmpty().isNotBlank())
        }
    }
    @Test fun activeHashLayerDisclosesEicarOnlyLimitation() {
        val layer = DetectionCoverage.status("local-hash-definitions")
        assertEquals(DetectionLayerState.ACTIVE_LIMITED, layer?.state)
        assertTrue(layer?.reason.orEmpty().contains("EICAR-only"))
    }
}
