package com.vibesync.antivirus.core.engine

enum class RiskSeverity { LOW, MEDIUM, HIGH }

data class RiskFinding(
    val ruleId: String,
    val severity: RiskSeverity,
    val evidence: String,
    val confidence: Int,
    /** Original component/file identifiers, kept distinct from explanatory UI copy. */
    val details: List<String> = emptyList()
) {
    init {
        require(ruleId.isNotBlank())
        require(evidence.isNotBlank())
        require(confidence in 0..100)
    }
}

data class RiskReport(
    val findings: List<RiskFinding>,
    val riskScore: Int,
    val observations: List<String> = emptyList(),
    val limitations: List<String> = listOf(
        "Known-bad certificate fingerprint list: DISABLED (no reviewed local list is bundled).",
        "Requested-permission/API comparison uses bounded DEX string evidence, not complete disassembly; reflection, native code and dynamic loading may evade it.",
        "Packer/entropy indicators are heuristic and may flag legitimate protectors or compressed/encrypted content."
    ),
    val yaraResult: YaraScanResult? = null,
    /** Only populated when a validated, digest-matched local model was successfully run. */
    val mlProbability: Float? = null
) {
    init { require(riskScore in 0..100) }
    val isSuspicious: Boolean get() = riskScore >= 45
}

data class ComponentExposure(
    val kind: String,
    val name: String,
    val exported: Boolean,
    val permission: String? = null,
    val readPermission: String? = null,
    val writePermission: String? = null
)
