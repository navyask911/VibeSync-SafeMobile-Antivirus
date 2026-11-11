package com.vibesync.antivirus.data.local

import java.time.DayOfWeek
import java.time.LocalDate
import java.time.ZoneId
import java.time.temporal.TemporalAdjusters

data class ScanOutcomeTotals(val threats: Long = 0, val noMatch: Long = 0, val other: Long = 0)
data class ScanDayCount(val day: String, val scans: Long)
data class ScanAnalytics(val totals: ScanOutcomeTotals = ScanOutcomeTotals(), val daily: List<Long> = List(7) { 0L })

/** Local calendar boundaries, including daylight-saving changes; not fixed 24-hour buckets. */
data class AnalyticsWeek(val monday: LocalDate, val zone: ZoneId) {
    val days: List<LocalDate> get() = List(7) { monday.plusDays(it.toLong()) }
    val startMillis: Long get() = monday.atStartOfDay(zone).toInstant().toEpochMilli()
    val endMillis: Long get() = monday.plusDays(7).atStartOfDay(zone).toInstant().toEpochMilli()
    fun counts(rows: List<ScanDayCount>): List<Long> {
        val byDate = rows.associate { it.day to it.scans.coerceAtLeast(0) }
        return days.map { byDate[it.toString()] ?: 0L }
    }
    companion object {
        fun current(date: LocalDate = LocalDate.now(), zone: ZoneId = ZoneId.systemDefault()) =
            AnalyticsWeek(date.with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)), zone)
    }
}
