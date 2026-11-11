package com.vibesync.antivirus.core.engine

data class ModelInferenceResult(val enabled: Boolean, val riskScore: Float? = null, val reason: String)

/** Never fabricates a score while a trained and evaluated model artifact is absent. */
class OfflineTfliteClassifier {
    fun classify(permissionFeatures: FloatArray, manifestFeatures: FloatArray): ModelInferenceResult {
        require(permissionFeatures.all { it.isFinite() }) { "Permission features must be finite." }
        require(manifestFeatures.all { it.isFinite() }) { "Manifest features must be finite." }
        return ModelInferenceResult(false, null, DISABLED_REASON)
    }
    companion object {
        const val DISABLED_REASON = "Disabled: no trained and validated malware_model.tflite is bundled."
    }
}
