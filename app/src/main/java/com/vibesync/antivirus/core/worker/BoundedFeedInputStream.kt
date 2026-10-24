package com.vibesync.antivirus.core.worker

import java.io.FilterInputStream
import java.io.InputStream
import java.net.URI

/** Streaming size guard for decompressed feed bodies; this never buffers the whole feed. */
internal class BoundedFeedInputStream(input: InputStream, private val maxBytes: Long) : FilterInputStream(input) {
    private var count = 0L
    init { require(maxBytes >= 0L) { "Maximum feed size must be non-negative." } }
    override fun read(): Int { val value = super.read(); if (value >= 0) addCount(1L); return value }
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        val read = super.read(buffer, offset, length)
        if (read > 0) addCount(read.toLong())
        return read
    }
    private fun addCount(amount: Long) {
        if (amount > maxBytes - count) throw FeedSizeLimitException()
        count += amount
    }
}

internal object FeedRedirectPolicy {
    fun resolve(current: URI, location: String, authKeyPresent: Boolean): URI {
        if (!current.scheme.equals("https", true) || current.host.isNullOrBlank()) throw FeedConfigurationException("Feed URL or redirect must use HTTPS.")
        val next = runCatching { current.resolve(location) }.getOrElse { throw FeedConfigurationException("Feed redirect target is invalid.") }
        if (!next.scheme.equals("https", true) || next.host.isNullOrBlank()) throw FeedConfigurationException("Insecure feed redirects are blocked.")
        if (authKeyPresent && !next.host.equals(current.host, true)) throw FeedConfigurationException("Cross-host redirects are blocked when an Auth-Key is set.")
        return next
    }
}

class FeedSizeLimitException : java.io.IOException("Threat feed exceeded the maximum size.")
