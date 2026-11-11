package com.vibesync.antivirus.core.hashdb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class HashDatabaseFormatTest {
    @Test fun parsesMultiAlgorithmSignedDatabase() {
        val source = """
            # SAFEHASH version=7 source=UnitTest license=CC0-1.0
            md5:44d88612fea8a8f36de82e1278abb02f:EICAR test marker
            sha1:3395856ce81f2b7382dee72602f798b642f14140:EICAR test marker
            sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:EICAR test marker
        """.trimIndent().toByteArray(Charsets.UTF_8)

        val parsed = HashDatabaseFormat.parse(source)
        assertEquals(7L, parsed.version)
        assertEquals(3, parsed.records.size)
        assertEquals(HashAlgorithm.SHA1, parsed.records[1].algorithm)
        assertEquals("eicar test marker", parsed.records[0].threatName.lowercase())
    }

    @Test fun parsesClamAvStyleHdbAndHsbRecords() {
        val md5 = """
            # SAFEHASH version=8 source=ClamCompat license=CC0-1.0
            44d88612fea8a8f36de82e1278abb02f:68:EICAR-Test-File
        """.trimIndent().toByteArray(Charsets.UTF_8)
        val sha256 = """
            # SAFEHASH version=9 source=ClamCompat license=CC0-1.0
            275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f:68:EICAR-Test-File
        """.trimIndent().toByteArray(Charsets.UTF_8)

        assertEquals(HashAlgorithm.MD5, HashDatabaseFormat.parse(md5, HashAlgorithm.MD5).records.single().algorithm)
        assertEquals(HashAlgorithm.SHA256, HashDatabaseFormat.parse(sha256, HashAlgorithm.SHA256).records.single().algorithm)
        assertEquals(68L, HashDatabaseFormat.parse(md5, HashAlgorithm.MD5).records.single().fileSize)
    }

    @Test fun rejectsDuplicateAndMalformedRows() {
        val duplicate = """
            # SAFEHASH version=1 source=UnitTest license=CC0-1.0
            md5:44d88612fea8a8f36de82e1278abb02f:one
            md5:44d88612fea8a8f36de82e1278abb02f:two
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
