package com.vibesync.antivirus.core.hashdb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HashDatabaseFormatTest {
    @Test fun parsesMultiAlgorithmSignedDatabase() {
        val source = """
            # SAFEHASH version=7 source=UnitTest license=CC0-1.0
            md5:900150983cd24fb0d6963f7d28e17f72:Sample test record
            sha1:a9993e364706816aba3e25717850c26c9cd0d89d:Sample test record
            sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:EICAR test marker
        """.trimIndent().toByteArray(Charsets.UTF_8)

        val parsed = HashDatabaseFormat.parse(source)
        assertEquals(7L, parsed.version)
        assertEquals(3, parsed.records.size)
        assertEquals(HashAlgorithm.SHA1, parsed.records[1].algorithm)
        assertEquals(HashAlgorithm.SHA256, parsed.records[2].algorithm)
        assertEquals("eicar test marker", parsed.records[2].threatName.lowercase())
    }

    @Test fun parsesClamAvStyleHdbAndHsbRecords() {
        val md5 = """
            # SAFEHASH version=8 source=ClamCompat license=CC0-1.0
            900150983cd24fb0d6963f7d28e17f72:3:Sample-Test-File
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val sha256 = """
            # SAFEHASH version=9 source=ClamCompat license=CC0-1.0
            275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:EICAR-Test-File
        """.trimIndent().toByteArray(Charsets.UTF_8)

        assertEquals(HashAlgorithm.MD5, HashDatabaseFormat.parse(md5, HashAlgorithm.MD5).records.single().algorithm)
        assertEquals(HashAlgorithm.SHA256, HashDatabaseFormat.parse(sha256, HashAlgorithm.SHA256).records.single().algorithm)
        assertEquals(3L, HashDatabaseFormat.parse(md5, HashAlgorithm.MD5).records.single().fileSize)
    }

    @Test fun rejectsDuplicateAndMalformedRows() {
        val duplicate = """
            # SAFEHASH version=1 source=UnitTest license=CC0-1.0
            md5:900150983cd24fb0d6963f7d28e17f72:one
            md5:900150983cd24fb0d6963f7d28e17f72:two
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val malformed = """
            # SAFEHASH version=1 source=UnitTest license=CC0-1.0
            sha256:not-a-hash:bad
        """.trimIndent().toByteArray(Charsets.UTF_8)

        assertThrows(IllegalArgumentException::class.java) { HashDatabaseFormat.parse(duplicate) }
        assertThrows(IllegalArgumentException::class.java) { HashDatabaseFormat.parse(malformed) }
        assertThrows(IllegalArgumentException::class.java) { HashDatabaseFormat.parse(byteArrayOf(0x23, 0x20, 0x53)) }
    }

    @Test fun rejectsEmptyOrOversizedDatabase() {
        assertThrows(IllegalArgumentException::class.java) { HashDatabaseFormat.parse(byteArrayOf()) }
        assertThrows(IllegalArgumentException::class.java) {
            HashDatabaseFormat.parse(ByteArray(HashDatabaseFormat.MAX_DATABASE_BYTES + 1))
        }
    }
}
