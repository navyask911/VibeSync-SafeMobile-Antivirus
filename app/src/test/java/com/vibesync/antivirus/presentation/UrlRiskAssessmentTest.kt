package com.vibesync.antivirus.presentation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UrlRiskAssessmentTest {
    @Test fun rejectsNonHttpSchemes() {
        assertTrue(UrlRiskAssessment.assess("javascript:alert(1)").invalid)
        assertTrue(UrlRiskAssessment.assess("file:///etc/passwd").invalid)
    }

    @Test fun flagsClearRiskIndicatorsForReview() {
        assertTrue(UrlRiskAssessment.assess("http://example.com").suspicious)
        assertTrue(UrlRiskAssessment.assess("https://user@example.com/path").suspicious)
        assertTrue(UrlRiskAssessment.assess("https://bit.ly/abc").suspicious)
    }

    @Test fun httpsHostnameWithoutHeuristicMatchDoesNotClaimSafety() {
        val result = UrlRiskAssessment.assess("https://example.com")
        assertFalse(result.invalid)
        assertFalse(result.suspicious)
        assertEquals("example.com", result.host)
    }

    @Test fun rejectsMalformedOrEmptyValues() {
        assertTrue(UrlRiskAssessment.assess("").invalid)
        assertTrue(UrlRiskAssessment.assess("https://").invalid)
    }
}
