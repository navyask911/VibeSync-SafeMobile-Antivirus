package com.vibesync.antivirus.core.engine

import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BoundedZipArchiveInspectorTest {
    @Test
    fun discoversNestedZipEntriesAndReturnsLeafPayloads() = runBlocking {
        val nested = zipOf("payload/eicar.txt" to "EICAR test payload".toByteArray())
        val root = zipFile(
            "readme.txt" to "outer".toByteArray(),
            "assets/nested.zip" to nested
        )
        try {
            val found = mutableListOf<ArchiveEntryPayload>()
            val outcome = BoundedZipArchiveInspector.inspect(root, includeAllLeafEntries = true) {
                found += it
            }
            assertTrue(outcome.complete)
            assertEquals(2, outcome.inspectedEntries)
            assertTrue(found.any { it.entryName.endsWith("readme.txt") })
            assertTrue(found.any { it.entryName.contains("nested.zip!/payload/eicar.txt") })
            assertEquals(
                "EICAR test payload",
                String(found.first { it.entryName.endsWith("eicar.txt") }.bytes)
            )
        } finally {
            root.delete()
        }
    }

    @Test
    fun apkModeDoesNotBufferLargeUnrelatedAssetsAndInspectsZipEntries() = runBlocking {
        val nested = zipOf("payload.txt" to "inside".toByteArray())
        val apk = zipFile(
            "AndroidManifest.xml" to byteArrayOf(1, 2),
            "classes.dex" to byteArrayOf(3, 4),
            "assets/payload.zip" to nested,
            "res/raw/ordinary.bin" to ByteArray(512) { 5 }
        )
        try {
            val found = mutableListOf<ArchiveEntryPayload>()
            val outcome = BoundedZipArchiveInspector.inspect(apk, includeAllLeafEntries = false) {
                found += it
            }
            assertTrue(outcome.complete)
            assertEquals(1, outcome.inspectedEntries)
            assertTrue(found.single().entryName.contains("payload.zip!/payload.txt"))
        } finally {
            apk.delete()
        }
    }


    @Test
    fun nonZipResourceWithZipSuffixInsideApkDoesNotCreateFalsePartialCoverage() = runBlocking {
        val apk = zipFile(
            "AndroidManifest.xml" to byteArrayOf(1, 2),
            "classes.dex" to byteArrayOf(3, 4),
            "assets/metadata.zip" to byteArrayOf(5, 6, 7, 8)
        )
        try {
            val found = mutableListOf<ArchiveEntryPayload>()
            val outcome = BoundedZipArchiveInspector.inspect(apk, includeAllLeafEntries = false) {
                found += it
            }
            assertTrue(outcome.complete)
            assertTrue(found.any { it.entryName.endsWith("metadata.zip") })
        } finally {
            apk.delete()
        }
    }

    @Test
    fun apkWithMoreThanTheOldEntryLimitStillCompletesWithinTheNewBound() = runBlocking {
        val entries = Array(2_100) { index ->
            "res/raw/item_$index.bin" to byteArrayOf(index.toByte())
        }
        val apk = zipFile(*entries)
        try {
            val outcome = BoundedZipArchiveInspector.inspect(apk, includeAllLeafEntries = false) { }
            assertTrue(outcome.complete)
        } finally {
            apk.delete()
        }
    }

    @Test
    fun zipNamedOrdinaryFileInStandardArchiveDoesNotCreateFalsePartialCoverage() = runBlocking {
        val root = zipFile(
            "assets/metadata.zip" to byteArrayOf(1, 2, 3, 4, 5),
            "assets/readme.txt" to "ordinary content".toByteArray()
        )
        try {
            val found = mutableListOf<ArchiveEntryPayload>()
            val outcome = BoundedZipArchiveInspector.inspect(root, includeAllLeafEntries = true) {
                found += it
            }
            assertTrue(outcome.complete)
            assertTrue(found.any { it.entryName.endsWith("metadata.zip") })
        } finally {
            root.delete()
        }
    }

    @Test
    fun malformedNestedZipPayloadWithZipSignatureIsReportedAsIncomplete() = runBlocking {
        val root = zipFile(
            "assets/malformed.zip" to byteArrayOf(0x50, 0x4b, 0x03, 0x04, 0x01),
            "assets/readme.txt" to "ordinary content".toByteArray()
        )
        try {
            val found = mutableListOf<ArchiveEntryPayload>()
            val outcome = BoundedZipArchiveInspector.inspect(root, includeAllLeafEntries = true) {
                found += it
            }
            assertFalse(outcome.complete)
            assertTrue(outcome.reason.orEmpty().isNotBlank())
            assertTrue(found.any { it.entryName.endsWith("readme.txt") })
        } finally {
            root.delete()
        }
    }

    @Test
    fun corruptRootArchiveDoesNotReportCompleteInspection() = runBlocking {
        val root = File.createTempFile("safe-mobile-corrupt-archive-", ".zip")
        root.writeBytes("not a ZIP file".toByteArray())
        try {
            val outcome = BoundedZipArchiveInspector.inspect(root, includeAllLeafEntries = true) { }
            assertFalse(outcome.complete)
            assertTrue(outcome.reason.orEmpty().contains("no readable file entries"))
        } finally {
            root.delete()
        }
    }

    private fun zipFile(vararg entries: Pair<String, ByteArray>): File {
        val file = File.createTempFile("safe-mobile-archive-", ".zip")
        file.writeBytes(zipOf(*entries))
        return file
    }

    private fun zipOf(vararg entries: Pair<String, ByteArray>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            entries.forEach { (name, bytes) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }
}
