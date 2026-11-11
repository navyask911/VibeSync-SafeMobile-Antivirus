package com.vibesync.antivirus.core.engine

/** Unified local verdict. Malware is true only after an exact local hash/IOC match. */
data class ThreatVerdict(
    val packageName: String,
    val riskScore: Float,
    val reasons: List<String>,
    val isMalware: Boolean,
    val layerStatuses: List<DetectionLayerStatus> = DetectionCoverage.layers
) {
    init {
        require(packageName.isNotBlank())
        require(riskScore.isFinite() && riskScore in 0f..1f)
    }
}
