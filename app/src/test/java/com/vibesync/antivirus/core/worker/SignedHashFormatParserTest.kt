package com.vibesync.antivirus.core.worker

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class SignedHashFormatParserTest {
    private suspend fun parse(text: String, format: String): List<com.vibesync.antivirus.data.local.MalwareHashEntity> {
        val rows = mutableListOf<com.vibesync.antivirus.data.local.MalwareHashEntity>()
        SignedHashFormatParser().parse(
            ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)), format, "signed-fixture"
        ) { rows.addAll(it) }
        return rows
    }
    @Test fun acceptsMd5HdbWithExactSize() = runBlocking {
        val items = parse("a".repeat(32) + ":68:Test.EICAR\n", "hdb")
        assertEquals(1, items.size)
        assertEquals(68L, items.single().fileSize)
        assertEquals("a".repeat(32), items.single().md5Hash)
    }
    @Test fun acceptsSha1AndSha256Hsb() = runBlocking {
        val items = parse("a".repeat(40) + ":19:Test.SHA1\n" + "b".repeat(64) + ":20:Test.SHA256\n", "hsb")
        assertEquals(2, items.size)
        assertEquals("a".repeat(40), items[0].sha1Hash)
        assertEquals("b".repeat(64), items[1].sha256Hash)
    }
    @Test fun acceptsExplicitSdbAlgorithms() = runBlocking {
        val rows = parse("sha1:" + "a".repeat(40) + ":0:Test.SHA1\n", "sdb")
        assertEquals("a".repeat(40), rows.single().sha1Hash)
    }
    @Test fun rejectsWildcardSizeAndMalformedLabels() = runBlocking {
        assertTrue(runCatching { parse("a".repeat(32) + ":*:Test\n", "hdb") }.isFailure)
        assertTrue(runCatching { parse("a".repeat(32) + ":1:Unknown:Extra\n", "hdb") }.isFailure)
    }
    @Test fun rejectsWrongDigestLengthAndWrongFormat() = runBlocking {
        assertTrue(runCatching { parse("b".repeat(40) + ":12:Test\n", "hdb") }.isFailure)
        assertTrue(runCatching { parse("b".repeat(32) + ":12:Test\n", "hsb") }.isFailure)
        assertTrue(runCatching { parse("sha256:garbage:12:Test\n", "sdb") }.isFailure)
    }
}
