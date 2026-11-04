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
    fun extractsBinaryManifestAndEveryRootDexWithoutWritingExtractedFiles() = runBlocking {
        val apk = createApk(
            "AndroidManifest.xml" to byteArrayOf(0x03, 0x00, 0x08, 0x00),
            "classes.dex" to byteArrayOf(1, 2, 3),
            "classes10.dex" to byteArrayOf(4, 5, 6)
        )
        try {
            val outcome = ApkContentExtractor().extract(apk)
            assertTrue(outcome is ApkExtractionOutcome.Complete)
            val components = (outcome as ApkExtractionOutcome.Complete).components
            assertEquals(
                listOf("AndroidManifest.xml", "classes.dex", "classes10.dex"),
                components.map { it.entryName }
            )
            assertEquals(0x03, components.first().bytes[0].toInt())
        } finally {
            apk.delete()
        }
    }

    @Test
    fun missingDexReturnsIncompleteRatherThanClean() = runBlocking {
        val apk = createApk("AndroidManifest.xml" to byteArrayOf(1, 2, 3))
        try {
            val outcome = ApkContentExtractor().extract(apk)
            assertTrue(outcome is ApkExtractionOutcome.Incomplete)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun missingManifestReturnsIncompleteRatherThanClean() = runBlocking {
        val apk = createApk("classes.dex" to byteArrayOf(1, 2, 3))
        try {
            val outcome = ApkContentExtractor().extract(apk)
            assertTrue(outcome is ApkExtractionOutcome.Incomplete)
        } finally {
            apk.delete()
        }
    }

    private fun createApk(vararg entries: Pair<String, ByteArray>): File {
        val apk = File.createTempFile("safe-mobile-yara-extractor-", ".apk")
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
