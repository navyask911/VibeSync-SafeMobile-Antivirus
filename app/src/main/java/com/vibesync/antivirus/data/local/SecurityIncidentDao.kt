package com.vibesync.antivirus.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface SecurityIncidentDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(incident: SecurityIncidentEntity)

    @Query("SELECT * FROM security_incidents ORDER BY occurred_at DESC LIMIT :limit")
    fun observeRecent(limit: Int = 100): Flow<List<SecurityIncidentEntity>>

    @Query("SELECT * FROM security_incidents WHERE event_id = :eventId LIMIT 1")
    suspend fun findById(eventId: String): SecurityIncidentEntity?

    @Query("SELECT * FROM security_incidents ORDER BY occurred_at DESC LIMIT :limit")
    suspend fun listRecent(limit: Int = 100): List<SecurityIncidentEntity>
}
