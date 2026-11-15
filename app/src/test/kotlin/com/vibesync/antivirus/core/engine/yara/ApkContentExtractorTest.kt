package com.vibesync.antivirus.core.engine.yara

import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkContentExtractorTest {

    @Test
    fun streamsOnlyBinaryManifestAndRootDexEntriesOneAtATime() = runBlocking {
        val apk = createApk(
            "res/drawable/icon.png" to ByteArray(128 * 1024) { 7 },
            "assets/payload.bin" to ByteArray(64 * 1024) { 8 },
            "lib/arm64-v8a/classes.dex" to byteArrayOf(9, 9, 9),
            "AndroidManifest.xml" to byteArrayOf(0x03, 0x00, 0x08, 0x00),
            "classes.dex" to byteArrayOf(1, 2, 3),
            "classes10.dex" to byteArrayOf(4, 5, 6)
        )
        try {
            val names = mutableListOf<String>()
            val data = mutableListOf<ByteArray>()
            val outcome = ApkContentExtractor().forEachComponent(apk) { component ->
                names += component.entryName
                data += component.bytes
                true
            }
            assertTrue(outcome is ApkExtractionOutcome.Complete)
            assertEquals(
                listOf("AndroidManifest.xml", "classes.dex", "classes10.dex"),
                names
            )
            assertEquals(names, (outcome as ApkExtractionOutcome.Complete).entryNames)
            assertEquals(0x03, data.first()[0].toInt())
            assertEquals(listOf(1, 2, 3), data[1].map { it.toInt() })
        } finally {
            apk.delete()
        }
    }

    @Test
    fun consumerCanStopStreamingWithoutReportingClean() = runBlocking {
        val apk = createApk(
            "AndroidManifest.xml" to byteArrayOf(1),
            "classes.dex" to byteArrayOf(2)
        )
        try {
            val outcome = ApkContentExtractor().forEachComponent(apk) { false }
            assertTrue(outcome is ApkExtractionOutcome.Incomplete)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun missingDexReturnsIncompleteRatherThanClean() = runBlocking {
        val apk = createApk("AndroidManifest.xml" to byteArrayOf(1, 2, 3))
        try {
            val outcome = ApkContentExtractor().forEachComponent(apk) { true }
            assertTrue(outcome is ApkExtractionOutcome.Incomplete)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun missingManifestReturnsIncompleteRatherThanClean() = runBlocking {
        val apk = createApk("classes.dex" to byteArrayOf(1, 2, 3))
        try {
            val outcome = ApkContentExtractor().forEachComponent(apk) { true }
            assertTrue(outcome is ApkExtractionOutcome.Incomplete)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun oversizedTargetDexReturnsIncompleteBeforeBufferingTheEntry() = runBlocking {
        val apk = createApk(
            "AndroidManifest.xml" to byteArrayOf(1),
            "classes.dex" to ByteArray(16 * 1024 * 1024 + 1)
        )
        try {
            val outcome = ApkContentExtractor().forEachComponent(apk) { true }
            assertTrue(outcome is ApkExtractionOutcome.Incomplete)
        } finally {
            apk.delete()
        }
    }

    private fun createApk(vararg entries: Pair<String, ByteArray>): File {
        val apk = File.createTempFile("safe-mobile-yara-stream-", ".apk")
        ZipOutputStream(FileOutputStream(apk)).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return apk
    }
}
