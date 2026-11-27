package com.vibesync.antivirus.core.engine

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

object ScanReportFormatter {
    /** Uses the device local timezone by default and includes its timezone abbreviation. */
    fun formatTimestamp(
        timestampMillis: Long,
        locale: Locale = Locale.getDefault(),
        timeZone: TimeZone = TimeZone.getDefault()
    ): String = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", locale).apply {
        this.timeZone = timeZone
    }.format(Date(timestampMillis))
}
