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

 @Query("""SELECT COALESCE(SUM(CASE WHEN verdict = 'THREAT' THEN 1 ELSE 0 END), 0) AS threats,
  COALESCE(SUM(CASE WHEN verdict = 'NO_MATCH' THEN 1 ELSE 0 END), 0) AS noMatch,
  COALESCE(SUM(CASE WHEN verdict NOT IN ('THREAT', 'NO_MATCH') THEN 1 ELSE 0 END), 0) AS other
  FROM scan_audits""")
 fun observeOutcomeTotals(): Flow<ScanOutcomeTotals>

 // One full scan can create hundreds of audit rows. Count its session once, on its first day.
 @Query("""SELECT strftime('%Y-%m-%d', firstScan / 1000, 'unixepoch', 'localtime') AS day, COUNT(*) AS scans
  FROM (SELECT MIN(scan_timestamp) AS firstScan FROM scan_audits GROUP BY
   CASE WHEN scan_session_id = '' THEN 'legacy:' || id ELSE 'session:' || scan_session_id END)
  WHERE firstScan >= :start AND firstScan < :end GROUP BY day ORDER BY day""")
 fun observeWeeklySessions(start: Long, end: Long): Flow<List<ScanDayCount>>
}
