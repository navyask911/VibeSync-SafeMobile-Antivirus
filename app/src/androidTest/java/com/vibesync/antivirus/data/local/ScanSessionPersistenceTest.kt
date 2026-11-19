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
    fun notScannedRowsAreRetryableAndReplacementPersistsTechnicalMetadata() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java)
            .allowMainThreadQueries().build()
        try {
            val dao = database.threatDao()
            val sessionId = "not-scanned-retry"
            val pendingKey = "app:com.example.pending"
            val doneKey = "app:com.example.done"
            dao.upsertScanSession(
                ScanSessionEntity(sessionId, "PERIODIC_DEEP_SCAN", 1000L, status = ScanSessionEntity.IN_PROGRESS)
            )
            dao.upsertScanSessionState(
                ScanSessionState(sessionId, totalItems = 2, scanType = "deep",
                    operationType = "PERIODIC_DEEP_SCAN", isManual = false)
            )
            dao.insertScanSessionItem(
                ScanSessionItemEntity(sessionId, pendingKey, "app", "Pending app", "NOT_SCANNED",
                    packageName = "com.example.pending", completedAt = 1100L)
            )
            dao.insertScanSessionItem(
                ScanSessionItemEntity(sessionId, doneKey, "app", "Done app", "NO_MATCH",
                    packageName = "com.example.done", completedAt = 1120L)
            )
            assertEquals(listOf(doneKey), dao.scanSessionItemKeys(sessionId))

            dao.insertScanSessionItem(
                ScanSessionItemEntity(
                    sessionId, pendingKey, "app", "Pending app", "NO_MATCH",
                    packageName = "com.example.pending", durationMs = 37L, completedAt = 1200L,
                    apkSizeBytes = 4096L, scanSource = "FRESH",
                    analysisStages = "HASH,YARA,ML,VERDICT"
                )
            )
            val rows = dao.scanSessionItems(sessionId)
            assertEquals(2, rows.size)
            val replaced = rows.single { it.itemKey == pendingKey }
            assertEquals("NO_MATCH", replaced.verdict)
            assertEquals(37L, replaced.durationMs)
            assertEquals(4096L, replaced.apkSizeBytes)
            assertEquals("HASH,YARA,ML,VERDICT", replaced.analysisStages)
            assertEquals(setOf(pendingKey, doneKey), dao.scanSessionItemKeys(sessionId).toSet())
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
