package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MetricsDocumentParserTest {
    @Test fun preservesUnmeasuredMetricsAndReasonsFromMetricsDocument() {
        val result = MetricsDocumentParser.parse("""
            **Status:** NOT MEASURED — corpus is missing.
            Last documentation review: 2026-10-24.
            | Metric | Value | Reason |
            |---|---|---|
            | TPR | NOT MEASURED | No test split. |
            | FPR | NOT MEASURED | No benign APKs. |
        """.trimIndent())
        assertTrue(result.status.contains("NOT MEASURED"))
        assertEquals("Last documentation review: 2026-10-24.", result.reviewed)
        assertEquals(2, result.rows.size)
        assertEquals("TPR", result.rows[0].metric)
        assertEquals("NOT MEASURED", result.rows[0].value)
        assertEquals("No test split.", result.rows[0].interpretation)
    }

    @Test fun missingMetricStatusDoesNotBecomeAClaimOfSuccess() {
        val result = MetricsDocumentParser.parse("No status or data.")
        assertTrue(result.status.startsWith("NOT MEASURED"))
        assertEquals(0, result.rows.size)
    }
}