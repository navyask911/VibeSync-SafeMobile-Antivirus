package com.vibesync.antivirus.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatFeedSyncStateDao {
    @Query("SELECT * FROM threat_feed_sync_state WHERE source_key = :sourceKey LIMIT 1")
    suspend fun get(sourceKey: String): ThreatFeedSyncStateEntity?

    @Query("SELECT * FROM threat_feed_sync_state ORDER BY last_attempt_at DESC LIMIT 1")
    fun observeLatest(): Flow<ThreatFeedSyncStateEntity?>

    @Query("SELECT MAX(last_success_at) FROM threat_feed_sync_state")
    fun observeLastSuccessfulSyncAt(): Flow<Long?>

    @Query("SELECT MAX(last_success_at) FROM threat_feed_sync_state")
    suspend fun getLastSuccessfulSyncAt(): Long?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(state: ThreatFeedSyncStateEntity)
}
