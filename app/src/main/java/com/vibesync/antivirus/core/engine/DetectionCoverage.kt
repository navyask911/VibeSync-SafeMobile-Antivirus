package com.vibesync.antivirus.core.engine

enum class DetectionLayerState { ACTIVE_LIMITED, HEURISTIC, DISABLED, CONDITIONAL }
data class DetectionLayerStatus(val id: String, val state: DetectionLayerState, val reason: String)

/** Runtime coverage declaration; keep it aligned with shipped assets and CI checks. */
object DetectionCoverage {
    val layers: List<DetectionLayerStatus> = listOf(
        DetectionLayerStatus("local-hash-definitions", DetectionLayerState.ACTIVE_LIMITED,
            "Legacy local matching has only the harmless EICAR test marker; not real-world coverage."),
        DetectionLayerStatus("signed-multi-hash-database", DetectionLayerState.DISABLED,
            "Signed MD5/SHA-1/SHA-256 matcher is implemented but no trusted signing key or vetted production signature database is bundled."),
        DetectionLayerStatus("deep-static-risk-report", DetectionLayerState.HEURISTIC,
            "Bounded APK static analysis emits advisory rule findings; no finding alone proves malware and known-bad signer fingerprints are disabled."),
        DetectionLayerStatus("permission-and-manifest", DetectionLayerState.HEURISTIC,
            "Permission combinations and visible manifest metadata are triage, not trained classification."),
        DetectionLayerStatus("root-hook-device-integrity", DetectionLayerState.HEURISTIC,
            "Root, hook, build-property, SELinux, debugger and emulator signals are offline heuristics."),
        DetectionLayerStatus("bloom-hash-index", DetectionLayerState.DISABLED,
            "A verified non-empty hypatia_bloom.db and manifest.json are not currently shipped."),
        DetectionLayerStatus("yara-dex-and-assets", DetectionLayerState.DISABLED,
            "No validated bundled rule pack loaded yet; no DEX rule scan claimed."),
        DetectionLayerStatus("tflite-permission-model", DetectionLayerState.DISABLED,
            "No trained, validated and legally distributable malware_model.tflite is currently shipped."),
        DetectionLayerStatus("offline-signer-attestation", DetectionLayerState.DISABLED,
            "An independently pinned expected signer fingerprint has not been configured."),
        DetectionLayerStatus("signed-feed-manifest", DetectionLayerState.CONDITIONAL,
            "Detached Ed25519 manifest verification and rollback protection are implemented; a trusted build-time public key and signed production feed are not configured.")
    )
    fun status(id: String): DetectionLayerStatus? {
        if (id == "yara-dex-and-assets") {
            val cap = BundledYaraEngine.capability
            return DetectionLayerStatus(id,
                if (cap.active) DetectionLayerState.ACTIVE_LIMITED else DetectionLayerState.DISABLED,
                cap.reason)
        }
        return layers.firstOrNull { it.id == id }
    }
}
