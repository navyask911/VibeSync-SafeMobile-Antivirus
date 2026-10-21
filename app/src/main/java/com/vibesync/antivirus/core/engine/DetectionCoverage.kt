package com.vibesync.antivirus.core.engine

enum class DetectionLayerState { ACTIVE_LIMITED, HEURISTIC, DISABLED }
data class DetectionLayerStatus(val id: String, val state: DetectionLayerState, val reason: String)

/** Runtime coverage declaration; keep it aligned with shipped assets and CI checks. */
object DetectionCoverage {
    val layers: List<DetectionLayerStatus> = listOf(
        DetectionLayerStatus("local-hash-definitions", DetectionLayerState.ACTIVE_LIMITED,
            "Local hash matching is active, but the bundled baseline is EICAR-only."),
        DetectionLayerStatus("permission-and-manifest", DetectionLayerState.HEURISTIC,
            "Permission combinations and visible manifest metadata are triage, not trained classification."),
        DetectionLayerStatus("root-hook-device-integrity", DetectionLayerState.HEURISTIC,
            "Root, hook, build-property, SELinux, debugger and emulator signals are offline heuristics."),
        DetectionLayerStatus("bloom-hash-index", DetectionLayerState.DISABLED,
            "A verified non-empty hypatia_bloom.db and manifest.json are not currently shipped."),
        DetectionLayerStatus("yara-dex-and-assets", DetectionLayerState.DISABLED,
            "No libyara JNI runtime or curated bundled YARA rules are currently shipped."),
        DetectionLayerStatus("tflite-permission-model", DetectionLayerState.DISABLED,
            "No trained and validated malware_model.tflite is currently shipped."),
        DetectionLayerStatus("offline-signer-attestation", DetectionLayerState.DISABLED,
            "An independently pinned expected signer fingerprint has not been configured."),
        DetectionLayerStatus("signed-feed-manifest", DetectionLayerState.DISABLED,
            "No detached Ed25519 manifest verification or feed-version rollback gate is implemented.")
    )
    fun status(id: String): DetectionLayerStatus? = layers.firstOrNull { it.id == id }
}
