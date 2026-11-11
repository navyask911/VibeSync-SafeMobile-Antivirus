package com.vibesync.antivirus.core.network

import java.io.IOException
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * A network client for tests that can only talk to the local MockWebServer.
 * Any accidental request to a public provider is rejected before DNS/socket access.
 */
class MockWebServerIsolationTest {
    private val server = MockWebServer()
    private lateinit var client: OkHttpClient
    private lateinit var allowedHost: String

    @Before
    fun setUp() {
        server.start()
        allowedHost = server.url("/").host
        client = OkHttpClient.Builder()
            .addInterceptor { chain ->
                val host = chain.request().url.host
                if (host != allowedHost) {
                    throw IOException("External network disabled in tests: $host")
                }
                chain.proceed(chain.request())
            }
            .build()
    }

    @After
    fun tearDown() {
        client.dispatcher.executorService.shutdown()
        client.connectionPool.evictAll()
        server.shutdown()
    }

    @Test
    fun localMockServerReturnsHardcodedSuccessfulFixture() {
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"source":"offline-fixture","count":21}""")
        )
        val request = Request.Builder().url(server.url("/tweetfeed/sha256")).build()

        client.newCall(request).execute().use { response ->
            assertEquals(200, response.code)
            assertEquals("""{"source":"offline-fixture","count":21}""", response.body?.string())
        }
        assertEquals("/tweetfeed/sha256", server.takeRequest().path)
    }

    @Test
    fun publicProviderRequestsAreBlockedBeforeTheyCanReachInternet() {
        val request = Request.Builder()
            .url("https://api.tweetfeed.live/v1/week/malware/sha256")
            .build()

        val error = try {
            client.newCall(request).execute().close()
            throw AssertionError("External provider request unexpectedly succeeded")
        } catch (expected: IOException) {
            expected
        }

        assertTrue(error.message.orEmpty().contains("External network disabled in tests"))
    }
}
