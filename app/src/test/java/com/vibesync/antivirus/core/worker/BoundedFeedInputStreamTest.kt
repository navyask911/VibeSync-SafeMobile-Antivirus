package com.vibesync.antivirus.core.worker

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.InputStream
import java.net.URI
import java.util.Arrays

class BoundedFeedInputStreamTest {
    private val limit = 100L * 1024L * 1024L
    private class GeneratedBytesInputStream(size: Long) : InputStream() {
        private var remaining = size
        override fun read(): Int { if (remaining <= 0L) return -1; remaining--; return 0 }
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (length == 0) return 0
            if (remaining <= 0L) return -1
            val count = minOf(length.toLong(), remaining).toInt()
            Arrays.fill(buffer, offset, offset + count, 0.toByte())
            remaining -= count
            return count
        }
    }
    private fun consume(input: InputStream): Long {
        val buffer = ByteArray(64 * 1024); var total = 0L
        input.use { stream -> while (true) { val count = stream.read(buffer); if (count < 0) break; total += count } }
        return total
    }
    @Test fun exactly100MiBIsAcceptedWithoutWholeFeedBuffering() {
        assertEquals(limit, consume(BoundedFeedInputStream(GeneratedBytesInputStream(limit), limit)))
    }
    @Test fun oneBytePast100MiBIsRejected() {
        val result = runCatching { consume(BoundedFeedInputStream(GeneratedBytesInputStream(limit + 1L), limit)) }
        assertTrue(result.exceptionOrNull() is FeedSizeLimitException)
    }
    @Test fun relativeHttpsRedirectIsAllowed() {
        val next = FeedRedirectPolicy.resolve(URI("https://feed.example.test/v1/feed.json"), "../v2/feed.json", true)
        assertEquals("https://feed.example.test/v2/feed.json", next.normalize().toString())
    }
    @Test fun crossHostRedirectIsAllowedOnlyWithoutAuthKey() {
        val current = URI("https://feed.example.test/feed.json")
        assertEquals("https://cdn.example.test/feed.json", FeedRedirectPolicy.resolve(current, "https://cdn.example.test/feed.json", false).toString())
        assertTrue(runCatching { FeedRedirectPolicy.resolve(current, "https://cdn.example.test/feed.json", true) }.isFailure)
    }
    @Test fun httpsDowngradeRedirectIsAlwaysRejected() {
        assertTrue(runCatching { FeedRedirectPolicy.resolve(URI("https://feed.example.test/feed.json"), "http://feed.example.test/feed.json", false) }.isFailure)
    }
}
