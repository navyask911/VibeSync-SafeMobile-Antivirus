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
    fun completedItemCheckpointPersistsAndCanBeResumed() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java).allowMainThreadQueries().build()
        try {
            val dao = database.threatDao()
            val id = "scan-resume-checkpoint"
            dao.upsertScanSession(ScanSessionEntity(id, "FULL_SCAN", 2_000L, status = ScanSessionEntity.IN_PROGRESS))
            dao.upsertScanSessionState(ScanSessionState(id, totalItems = 3, scannedItems = 0, scanType = "full", operationType = "FULL_DEVICE"))
            dao.insertScanSessionItem(ScanSessionItemEntity(id, "app:com.example.safe", "app",
                "protected-label", "NO_MATCH", packageName = "com.example.safe", completedAt = 2_100L))
            dao.updateScanSessionProgress(id, dao.countScanSessionItems(id), "protected-label")
            assertEquals(1, dao.findScanSessionState(id)?.scannedItems)
            assertEquals(listOf("app:com.example.safe"), dao.scanSessionItemKeys(id))
            assertEquals(id, dao.latestIncompleteManualScanState()?.sessionId)
            dao.markScanSessionStateComplete(id, 1)
            assertEquals(null, dao.latestIncompleteManualScanState())
        } finally { database.close() }
    }

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

 
    @Test
    fun periodicDeepScanIsVisibleToScanLabButIsNotAResumableManualSession() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            val dao = database.threatDao()
            val sessionId = "periodic-deep-scan-visible"
            dao.upsertScanSession(
                ScanSessionEntity(
                    sessionId = sessionId,
                    scanType = "PERIODIC_DEEP_SCAN",
                    startedAt = 3_000L,
                    status = ScanSessionEntity.IN_PROGRESS
                )
            )
            dao.upsertScanSessionState(
                ScanSessionState(
                    sessionId = sessionId,
                    totalItems = 2,
                    scannedItems = 1,
                    scanType = "deep",
                    operationType = "PERIODIC_DEEP_SCAN",
                    isManual = false
                )
            )

            assertEquals(sessionId, dao.observeLatestScanState().first()?.sessionId)
            assertEquals(null, dao.latestIncompleteManualScanState())

            // Scheduled sessions remain active for WorkManager, not manual-session cleanup.
            dao.markInProgressAsInterrupted()
            assertEquals(1, dao.observeScanSessionCounts().first().inProgress)

            dao.markScanSessionStateComplete(sessionId, 1)
            dao.markScanSessionCompleted(sessionId, 4_000L)
            assertEquals(sessionId, dao.latestCompletedScanState()?.sessionId)
            assertEquals(sessionId, dao.observeLatestScanState().first()?.sessionId)
        } finally {
            database.close()
        }
    }
}
