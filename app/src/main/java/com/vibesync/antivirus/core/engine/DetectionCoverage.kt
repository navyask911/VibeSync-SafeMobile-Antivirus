package com.vibesync.antivirus.core.engine

enum class DetectionLayerState { ACTIVE_LIMITED, HEURISTIC, DISABLED, CONDITIONAL }
data class DetectionLayerStatus(val id: String, val state: DetectionLayerState, val reason: String)

/**
 * This registry describes source-level capability state, not measured efficacy. It is not currently
 * attached to every UI ScanResult; docs remain the canonical user/reviewer-facing coverage matrix.
 */
object DetectionCoverage {
    val layers: List<DetectionLayerStatus> = listOf(
        DetectionLayerStatus("local-hash-definitions", DetectionLayerState.ACTIVE_LIMITED,
            "Local Room SHA-256 matching is active, but the bundled baseline contains only the harmless EICAR test marker."),
        DetectionLayerStatus("permission-and-manifest", DetectionLayerState.HEURISTIC,
            "Permission/service metadata combinations and debug-certificate checks provide triage only."),
        DetectionLayerStatus("root-hook-device-integrity", DetectionLayerState.HEURISTIC,
            "Offline root/hook/build-property/SELinux/debugger/emulator checks are best-effort and bypassable."),
        DetectionLayerStatus("bloom-hash-index", DetectionLayerState.DISABLED,
            "No verified non-empty hypatia_bloom.db is shipped and ordinary PackageScanner does not query the Bloom loader."),
        DetectionLayerStatus("yara-dex-and-assets", DetectionLayerState.DISABLED,
            "No built libyara JNI libraries or licence-reviewed rule set are shipped; no YARA scan occurs."),
        DetectionLayerStatus("tflite-permission-model", DetectionLayerState.DISABLED,
            "permission_risk.tflite is absent; the optional scorer returns null and the current scanner does not call inference."),
        DetectionLayerStatus("offline-signer-attestation", DetectionLayerState.DISABLED,
            "Expected release signer fingerprint is not configured or enforced by the normal scan/release path."),
        DetectionLayerStatus("signed-feed-manifest", DetectionLayerState.CONDITIONAL,
            "Detached Ed25519 signature, source binding, payload SHA-256 and strictly increasing version checks are implemented; a trusted public key and signed production feed are not configured.")
    )
    fun status(id: String): DetectionLayerStatus? = layers.firstOrNull { it.id == id }
}
