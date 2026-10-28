package com.vibesync.antivirus.data.local

import java.time.LocalDate
import java.time.ZoneId
import org.junit.Assert.*
import org.junit.Test

class AnalyticsWeekTest {
    @Test fun mondayToSundayUsesLocalCalendarAcrossDst() {
        val zone = ZoneId.of("America/Los_Angeles")
        val spring = AnalyticsWeek.current(LocalDate.of(2026, 3, 8), zone)
        assertEquals(LocalDate.of(2026, 3, 2), spring.monday)
        assertEquals(167L * 3_600_000L, spring.endMillis - spring.startMillis)
        val autumn = AnalyticsWeek.current(LocalDate.of(2026, 11, 1), zone)
        assertEquals(169L * 3_600_000L, autumn.endMillis - autumn.startMillis)
    }

    @Test fun absentDaysStayZeroAndOutOfWeekDataIsNotPlotted() {
        val week = AnalyticsWeek.current(LocalDate.of(2026, 10, 28), ZoneId.of("UTC"))
        assertEquals(listOf(0L, 0L, 4L, 0L, 0L, 0L, 2L), week.counts(listOf(
            ScanDayCount("2026-11-01", 2), ScanDayCount("2026-10-28", 4), ScanDayCount("2026-11-02", 99))))
        assertEquals(List(7) { 0L }, week.counts(emptyList()))
    }
}
