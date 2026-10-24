package com.vibesync.antivirus.core.engine

data class DetectionMetricRow(val metric: String, val value: String, val interpretation: String)
data class MetricsDocumentSummary(val status: String, val reviewed: String, val rows: List<DetectionMetricRow>)

/** Reads the checked-in metrics table verbatim; it never generates or estimates efficacy values. */
object MetricsDocumentParser {
    private val separator = Regex("^\\|[-| :]+\\|$")

    fun parse(markdown: String): MetricsDocumentSummary {
        val lines = markdown.lineSequence().map(String::trim).toList()
        val statusLine = lines.firstOrNull { it.startsWith("**Status:**") }
            ?: "**Status:** NOT MEASURED — the metrics status line is missing."
        val status = statusLine.removePrefix("**Status:**").trim().replace("**", "")
        val reviewed = lines.firstOrNull { it.startsWith("Last documentation review:") }.orEmpty()
        val rows = lines.asSequence()
            .filter { it.startsWith("|") && !separator.matches(it) }
            .map { it.trim('|').split('|').map(String::trim) }
            .filter { it.size >= 3 && it[0] != "Metric" }
            .map { DetectionMetricRow(it[0], it[1], it.drop(2).joinToString(" | ")) }
            .toList()
        return MetricsDocumentSummary(status, reviewed, rows)
    }
}