package com.vibesync.antivirus.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface ThreatFeedStagingDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertBatch(rows: List<ThreatFeedStagingEntity>)

    /** Keyset pagination bounds heap use even for very large feeds. */
    @Query("""
        SELECT * FROM threat_feed_staging
        WHERE import_id = :importId AND indicator_key > :afterIndicatorKey
        ORDER BY indicator_key ASC
        LIMIT :limit
    """)
    suspend fun nextBatch(importId: String, afterIndicatorKey: String, limit: Int): List<ThreatFeedStagingEntity>

    @Query("SELECT COUNT(*) FROM threat_feed_staging WHERE import_id = :importId")
    suspend fun countForImport(importId: String): Int

    @Query("DELETE FROM threat_feed_staging WHERE import_id = :importId")
    suspend fun deleteForImport(importId: String): Int

    @Query("DELETE FROM threat_feed_staging WHERE staged_at < :cutoff")
    suspend fun deleteStaleBefore(cutoff: Long): Int
}
