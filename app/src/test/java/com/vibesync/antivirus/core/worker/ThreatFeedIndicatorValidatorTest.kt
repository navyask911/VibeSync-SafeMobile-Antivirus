package com.vibesync.antivirus.core.worker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class ThreatFeedIndicatorValidatorTest {
    @Test fun normalizesSha256AndMd5ToLowercaseAndKeepsSource() {
        val row = ThreatFeedIndicatorValidator.normalize(
            ThreatFeedRecord(sha256 = "A".repeat(64), md5 = "B".repeat(32), threatName = "Test family"),
            "feed.example"
        )
        assertNotNull(row)
        assertEquals("a".repeat(64), row?.sha256Hash)
        assertEquals("b".repeat(32), row?.md5Hash)
        assertEquals("feed.example", row?.source)
        assertEquals("Test family", row?.threatName)
    }

    @Test fun normalizesDomainIndicatorsAndRejectsEmptyRecords() {
        val row = ThreatFeedIndicatorValidator.normalize(
            ThreatFeedRecord(iocValue = "Bad.Example.", iocType = "domain", threatName = "C2"),
            "feed.example"
        )
        assertEquals("bad.example", row?.iocValue)
        assertNull(ThreatFeedIndicatorValidator.normalize(ThreatFeedRecord(), "feed.example"))
    }

    @Test fun unsupportedOrMalformedHashesDoNotBecomeHashIndicators() {
        val row = ThreatFeedIndicatorValidator.normalize(
            ThreatFeedRecord(sha256 = "not-a-sha256", md5 = "bad"),
            "feed.example"
        )
        assertNull(row)
    }

    @Test fun promotesHashShapedIocsIntoHashColumns() {
        val sha = ThreatFeedIndicatorValidator.normalize(
            ThreatFeedRecord(iocValue = "E".repeat(64), iocType = "sha256_hash", threatName = "Hash IOC"),
            "threatfox-api.abuse.ch"
        )
        val md5 = ThreatFeedIndicatorValidator.normalize(
            ThreatFeedRecord(iocValue = "F".repeat(32), iocType = "md5_hash", threatName = "Hash IOC"),
            "threatfox-api.abuse.ch"
        )
        assertEquals("e".repeat(64), sha?.sha256Hash)
        assertNull(sha?.iocValue)
        assertEquals("f".repeat(32), md5?.md5Hash)
        assertNull(md5?.iocValue)
    }

    @Test fun genericHashFieldInfersSupportedHashLength() {
        val sha = ThreatFeedIndicatorValidator.normalize(ThreatFeedRecord(genericHash = "c".repeat(64)), "feed.example")
        val md5 = ThreatFeedIndicatorValidator.normalize(ThreatFeedRecord(genericHash = "d".repeat(32)), "feed.example")
        assertEquals("c".repeat(64), sha?.sha256Hash)
        assertEquals("d".repeat(32), md5?.md5Hash)
    }
}
