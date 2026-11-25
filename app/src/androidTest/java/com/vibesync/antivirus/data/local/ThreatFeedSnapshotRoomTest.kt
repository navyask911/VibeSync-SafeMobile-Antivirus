package com.vibesync.antivirus.data.local

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import com.vibesync.antivirus.data.repository.ThreatIntelligenceRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test

class ThreatFeedSnapshotRoomTest {
    private lateinit var database: ThreatDatabase
    private lateinit var repository: ThreatIntelligenceRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repository = ThreatIntelligenceRepository(
            database.malwareHashDao(),
            database.threatFeedSyncStateDao()
        )
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun observedSnapshotEmitsRoomIndicatorAndFeedStateChanges() = runBlocking {
        val initial = repository.observeSnapshot().first()
        assertEquals(0, initial.activeIndicatorCount)
        assertEquals(null, initial.latestSyncState)

        database.malwareHashDao().upsertBatch(
            listOf(
                MalwareHashEntity(
                    indicatorKey = "sha256:test",
                    sha256Hash = "a".repeat(64),
                    threatName = "Test marker",
                    source = "test-feed",
                    updatedAt = 100L
                )
            )
        )
        val withIndicator = repository.observeSnapshot().first { it.activeIndicatorCount == 1 }
        assertEquals(1, withIndicator.activeIndicatorCount)

        val sync = ThreatFeedSyncStateEntity(
            sourceKey = "feed-key",
            sourceHost = "feed.example",
            lastAttemptAt = 200L,
            lastSuccessAt = 200L,
            status = "SUCCESS",
            lastImportedCount = 1
        )
        database.threatFeedSyncStateDao().upsert(sync)
        val afterSync = repository.observeSnapshot().first {
            it.latestSyncState?.status == "SUCCESS" && it.lastSuccessfulSyncAt == 200L
        }
        assertNotNull(afterSync.latestSyncState)
        assertEquals(1, afterSync.activeIndicatorCount)
        assertEquals(1, afterSync.latestSyncState?.lastImportedCount)
    }
}
