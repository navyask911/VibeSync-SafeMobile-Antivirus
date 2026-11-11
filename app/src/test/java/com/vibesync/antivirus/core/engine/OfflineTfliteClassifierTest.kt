package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test

class OfflineTfliteClassifierTest {
    @Test fun absenceOfTrainedModelProducesNoScoreAndExplicitDisabledReason() {
        val result = OfflineTfliteClassifier().classify(
            permissionFeatures = floatArrayOf(0f, 1f, 0f),
            manifestFeatures = floatArrayOf(0f, 0.5f)
        )
        assertFalse(result.enabled)
        assertEquals(null, result.riskScore)
        assertNotNull(result.reason)
        assertEquals(OfflineTfliteClassifier.DISABLED_REASON, result.reason)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonFiniteInputInsteadOfReturningFakePrediction() {
        OfflineTfliteClassifier().classify(floatArrayOf(Float.NaN), floatArrayOf(0f))
    }
}