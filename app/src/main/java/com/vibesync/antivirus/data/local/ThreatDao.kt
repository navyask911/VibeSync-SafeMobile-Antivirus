package com.vibesync.antivirus.data.local
import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatDao {
 @Query("SELECT * FROM threat_signatures WHERE hash = :encryptedHash LIMIT 1")
 suspend fun findThreatByEncryptedHash(encryptedHash: String): ThreatSignature?
 @Insert(onConflict = OnConflictStrategy.REPLACE)
 suspend fun upsertSignatures(signatures: List<ThreatSignature>)
 @Query("SELECT COUNT(*) FROM threat_signatures")
 suspend fun countSignatures(): Int
 @Query("SELECT EXISTS(SELECT 1 FROM whitelist_entries WHERE hash = :encryptedHash)")
 suspend fun isHashWhitelisted(encryptedHash: String): Boolean
 @Insert(onConflict = OnConflictStrategy.REPLACE)
 suspend fun upsertWhitelistEntry(entry: WhiteListEntry)
 @Insert
 suspend fun insertAudit(audit: ScanAudit): Long
 @Query("SELECT * FROM scan_audits ORDER BY scan_timestamp DESC LIMIT 50")
 fun observeRecentAudits(): Flow<List<ScanAudit>>
}
