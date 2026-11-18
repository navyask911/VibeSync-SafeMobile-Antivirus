package com.vibesync.antivirus.core.engine

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanResultPublisherTest {
    @Test
    fun roomPublisherFailureIsLoggedAndDoesNotPreventNextPackage() = runTest {
        val logged = mutableListOf<Pair<String, Throwable>>()
        var nextPackagePublished = false
        val logger: (String, Throwable) -> Unit = { packageName, error ->
            logged += packageName to error
        }

        val firstPublished = publishScanResultSafely(
            packageName = "com.example.room-failure",
            publish = { throw IllegalStateException("Room insert failed") },
            logFailure = logger
        )
        val nextPublished = publishScanResultSafely(
            packageName = "com.example.next",
            publish = { nextPackagePublished = true },
            logFailure = logger
        )

        assertFalse(firstPublished)
        assertTrue(nextPublished)

        assertTrue(nextPackagePublished)
        assertEquals(1, logged.size)
        assertEquals("com.example.room-failure", logged.single().first)
        assertTrue(logged.single().second is IllegalStateException)
    }

    @Test
    fun callbackCancellationIsContainedWhileParentScanRemainsActive() = runTest {
        val logged = mutableListOf<Throwable>()

        publishScanResultSafely(
            packageName = "com.example.publisher-cancel",
            publish = { throw CancellationException("Room callback cancelled itself") },
            logFailure = { _, error -> logged += error }
        )

        assertTrue(currentCoroutineContext().isActive)
        assertEquals(1, logged.size)
        assertTrue(logged.single() is CancellationException)
    }

    @Test
    fun parentCancellationIsNotSwallowed() = runTest {
        val failures = mutableListOf<Throwable>()
        val child = launch {
            publishScanResultSafely(
                packageName = "com.example.parent-cancel",
                publish = {
                    currentCoroutineContext().cancel()
                    throw CancellationException("parent scan cancelled")
                },
                logFailure = { _, error -> failures += error }
            )
        }

        child.join()

        assertFalse(child.isActive)
        assertTrue(child.isCancelled)
        assertTrue(failures.isEmpty())
    }
}
