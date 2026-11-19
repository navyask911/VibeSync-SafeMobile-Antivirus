package com.vibesync.antivirus.core.engine

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Locale
import java.util.TimeZone

class ScanReportFormatterTest {
    @Test fun formatsDateAndExplicitTimezoneForTheReport() {
        assertEquals(
            "1970-01-01 00:00:00 UTC",
            ScanReportFormatter.formatTimestamp(0L, Locale.US, TimeZone.getTimeZone("UTC"))
        )
    }
}
