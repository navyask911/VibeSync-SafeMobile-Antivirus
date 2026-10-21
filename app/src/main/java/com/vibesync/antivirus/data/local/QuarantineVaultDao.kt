package com.vibesync.antivirus.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface QuarantineVaultDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entry: QuarantineVaultEntity)

    @Query("SELECT * FROM quarantine_vault_entries ORDER BY created_at DESC LIMIT :limit")
    fun observeRecent(limit: Int = 100): Flow<List<QuarantineVaultEntity>>

    @Query("SELECT * FROM quarantine_vault_entries ORDER BY created_at DESC LIMIT :limit")
    suspend fun listRecent(limit: Int = 100): List<QuarantineVaultEntity>

    @Query("SELECT * FROM quarantine_vault_entries WHERE vault_id = :vaultId LIMIT 1")
    suspend fun findById(vaultId: String): QuarantineVaultEntity?
}
