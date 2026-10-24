package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class YaraScannerTest {
    @Test fun readableFileReportsDisabledInsteadOfPretendingNoMatch() {
        val file = File.createTempFile("yara-disabled", ".apk")
        try {
            file.writeBytes(byteArrayOf(0x50, 0x4b, 0x03, 0x04))
            val result = YaraScanner().scan(file)
            assertEquals(YaraScanState.DISABLED, result.state)
            assertTrue(result.reason.orEmpty().contains("No libyara JNI runtime"))
            assertTrue(result.matchedRules.isEmpty())
        } finally {
            file.delete()
        }
    }

    @Test fun absentFileIsNotScanned() {
        val result = YaraScanner().scan(File("/this/path/does/not/exist/sample.apk"))
        assertEquals(YaraScanState.NOT_SCANNED, result.state)
    }
}