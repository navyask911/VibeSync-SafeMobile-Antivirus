package com.vibesync.antivirus.data.local

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ScanAnalyticsDaoTest {
    @Test fun aggregatesAllRowsAndCountsSessionsRatherThanScannedApps() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java).build()
        try {
            val dao = db.threatDao()
            val week = AnalyticsWeek.current()
            assertEquals(ScanOutcomeTotals(), dao.observeOutcomeTotals().first())
            val day = week.monday.plusDays(2).atTime(12, 0).atZone(week.zone).toInstant().toEpochMilli()
            suspend fun row(session: String, verdict: String, time: Long = day) {
                dao.insertAudit(ScanAudit(packageOrPath = "fixture", hash = "", scanTimestamp = time,
                    verdict = verdict, scanDuration = 1, scanSessionId = session))
            }
            repeat(100) { row("full-scan", "NO_MATCH") }
            repeat(2) { row("second-scan", "THREAT") }
            row("", "SUSPICIOUS"); row("", "NOT_SCANNED")
            row("cross-week", "NO_MATCH", week.startMillis - 1)
            row("cross-week", "NO_MATCH", day)
            assertEquals(ScanOutcomeTotals(2, 102, 2), dao.observeOutcomeTotals().first())
            val bars = week.counts(dao.observeWeeklySessions(week.startMillis, week.endMillis).first())
            assertEquals(listOf(0L, 0L, 4L, 0L, 0L, 0L, 0L), bars)
        } finally { db.close() }
    }
}
