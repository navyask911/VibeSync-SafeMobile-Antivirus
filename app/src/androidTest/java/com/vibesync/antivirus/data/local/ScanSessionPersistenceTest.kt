package com.vibesync.antivirus.data.local

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ScanSessionPersistenceTest {
    @Test
    fun liveCounterIncludesInProgressSessionAndTransitionsToCompleted() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java)
            .allowMainThreadQueries()
            .build()

        try {
            val dao = database.threatDao()
            val sessionId = "phase3-live-counter"

            dao.upsertScanSession(
                ScanSessionEntity(
                    sessionId = sessionId,
                    scanType = "TEST",
                    startedAt = 1_000L,
                    status = ScanSessionEntity.IN_PROGRESS
                )
            )

            val active = dao.observeScanSessionCounts().first()
            assertEquals(1, active.total)
            assertEquals(0, active.completed)
            assertEquals(1, active.inProgress)

            val completedAt = 1_234_567L
            dao.markScanSessionCompleted(sessionId, completedAt)

            val completed = dao.observeScanSessionCounts().first()
            assertEquals(1, completed.total)
            assertEquals(1, completed.completed)
            assertEquals(0, completed.inProgress)
            assertEquals(completedAt, dao.latestCompletedScanAt())
            assertEquals(completedAt, dao.observeLatestCompletedScanAt().first())
        } finally {
            database.close()
        }
    }
}
