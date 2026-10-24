package com.vibesync.antivirus.core.hashdb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class HashDatabaseBundleReaderTest {
    @Test fun readsExpectedDetachedBundleWithoutExtractingPaths() {
        val database = "# SAFEHASH version=1 source=UnitTest license=CC0-1.0\nmd5:44d88612fea8a8f36de82e1278abb02f:test\n".toByteArray()
        val signature = ByteArray(64) { 1 }
        val bytes = ByteArrayOutputStream().also { output ->
            ZipOutputStream(output).use { zip ->
                zip.putNextEntry(ZipEntry("hashes.sdb")); zip.write(database); zip.closeEntry()
                zip.putNextEntry(ZipEntry("hashes.sdb.sig")); zip.write(signature); zip.closeEntry()
            }
        }.toByteArray()

        val bundle = HashDatabaseBundleReader.read(ByteArrayInputStream(bytes))
        assertEquals("hashes.sdb", bundle.databaseName)
        assertEquals(String(database), String(bundle.databaseBytes))
        assertEquals(64, bundle.detachedSignatureBytes.size)
    }

    @Test fun rejectsZipSlipAndUnexpectedFiles() {
        val bytes = ByteArrayOutputStream().also { output ->
            ZipOutputStream(output).use { zip ->
                zip.putNextEntry(ZipEntry("../hashes.sdb")); zip.write(byteArrayOf(1)); zip.closeEntry()
            }
        }.toByteArray()
        assertThrows(IllegalArgumentException::class.java) {
            HashDatabaseBundleReader.read(ByteArrayInputStream(bytes))
        }
    }
}
