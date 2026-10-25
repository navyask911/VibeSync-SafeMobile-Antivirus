package com.vibesync.antivirus.core.worker

import com.vibesync.antivirus.data.local.MalwareHashEntity
import java.io.ByteArrayInputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ThreatFeedParserTest {
    @Test
    fun parsesCsvIncrementallyAndNormalizesHashAndDomainIndicators() = runBlocking {
        val sha256 = "a".repeat(64)
        val md5 = "b".repeat(32)
        val csv = listOf(
            "sha256,md5,ioc_type,ioc,threat_name",
            "$sha256,,,,\"Family, alpha\"",
            ",$md5,,,\"Legacy family\"",
            ",,domain,bad.example,\"C2 host\""
        ).joinToString("\n")
        val batches = mutableListOf<List<MalwareHashEntity>>()

        val total = ThreatFeedParser(batchSize = 2).parse(
            ByteArrayInputStream(csv.toByteArray(Charsets.UTF_8)),
            ThreatFeedFormat.CSV,
            "feed.example"
        ) { batches += it }

        val rows = batches.flatten()
        assertEquals(3L, total)
        assertEquals(listOf(2, 1), batches.map { it.size })
        assertTrue(rows.all { it.source == "feed.example" })
        assertEquals(sha256, rows[0].sha256Hash)
        assertEquals(md5, rows[1].md5Hash)
        assertEquals("bad.example", rows[2].iocValue)
        assertEquals("domain", rows[2].iocType)
        assertEquals("Family, alpha", rows[0].threatName)
    }

    @Test
    fun rejectsEmptyAuthoritativeSnapshotToProtectPreviouslyActiveIndicators() {
        assertThrows(FeedParseException::class.java) {
            requireNonEmptyAuthoritativeSnapshot(0L)
        }
    }

    @Test
    fun allowsNonEmptyAuthoritativeSnapshot() {
        requireNonEmptyAuthoritativeSnapshot(1L)
    }

    @Test
    fun rejectsMalformedCsvEvenAfterEarlierBatchesWereDeliveredToStaging() {
        val sha256 = "c".repeat(64)
        val badSha256 = "d".repeat(64)
        val csv = "sha256,threat_name\n$sha256,Valid row\n$badSha256,\"unterminated"
        var deliveredBatches = 0

        assertThrows(FeedParseException::class.java) {
            runBlocking {
                ThreatFeedParser(batchSize = 1).parse(
                    ByteArrayInputStream(csv.toByteArray(Charsets.UTF_8)),
                    ThreatFeedFormat.CSV,
                    "feed.example"
                ) { deliveredBatches += 1 }
            }
        }
        assertEquals(1, deliveredBatches)
    }
    @Test
    fun parsesSha1AndFileSizeFromCsvForSizeConstrainedMatching() = runBlocking {
        val digest = "d".repeat(40)
        val csv = "sha1,file_size,threat_name\n$digest,68,Size bound test"
        val rows = mutableListOf<MalwareHashEntity>()
        val total = ThreatFeedParser().parse(
            ByteArrayInputStream(csv.toByteArray(Charsets.UTF_8)),
            ThreatFeedFormat.CSV,
            "feed.example"
        ) { batch -> rows.addAll(batch) }
        assertEquals(1L, total)
        assertEquals(digest, rows.single().sha1Hash)
        assertEquals(68L, rows.single().fileSize)
    }

}
