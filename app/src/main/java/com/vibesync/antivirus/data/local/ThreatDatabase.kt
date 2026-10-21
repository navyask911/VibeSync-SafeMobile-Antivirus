package com.vibesync.antivirus.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
 entities = [ThreatSignature::class, ScanAudit::class, WhiteListEntry::class, MalwareHashEntity::class, ThreatFeedSyncStateEntity::class, ThreatFeedStagingEntity::class],
 version = 5, exportSchema = false
)
abstract class ThreatDatabase : RoomDatabase() {
 abstract fun threatDao(): ThreatDao
 abstract fun malwareHashDao(): MalwareHashDao
 abstract fun threatFeedSyncStateDao(): ThreatFeedSyncStateDao
 abstract fun threatFeedStagingDao(): ThreatFeedStagingDao

 companion object {
  val MIGRATION_1_2: Migration = object : Migration(1, 2) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("ALTER TABLE scan_audits ADD COLUMN scan_session_id TEXT NOT NULL DEFAULT ''")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_scan_audits_scan_session_id ON scan_audits(scan_session_id)")
   }
  }
  val MIGRATION_2_3: Migration = object : Migration(2, 3) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("ALTER TABLE scan_audits ADD COLUMN threat_event_id TEXT NOT NULL DEFAULT ''")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_scan_audits_threat_event_id ON scan_audits(threat_event_id)")
   }
  }
  /** Additive schema migration; the existing signature and scan-audit tables are preserved. */
  val MIGRATION_3_4: Migration = object : Migration(3, 4) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("CREATE TABLE IF NOT EXISTS malware_hashes (indicator_key TEXT NOT NULL, sha256_hash TEXT, md5_hash TEXT, ioc_value TEXT, ioc_type TEXT, threat_name TEXT NOT NULL, source TEXT NOT NULL, first_seen_at INTEGER, last_seen_at INTEGER, updated_at INTEGER NOT NULL, PRIMARY KEY(indicator_key))")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_malware_hashes_sha256_hash ON malware_hashes(sha256_hash)")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_malware_hashes_md5_hash ON malware_hashes(md5_hash)")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_malware_hashes_ioc_value ON malware_hashes(ioc_value)")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_malware_hashes_source_updated_at ON malware_hashes(source, updated_at)")
    database.execSQL("CREATE TABLE IF NOT EXISTS threat_feed_sync_state (source_key TEXT NOT NULL, source_host TEXT NOT NULL, last_attempt_at INTEGER NOT NULL, last_success_at INTEGER, status TEXT NOT NULL, last_error TEXT, last_imported_count INTEGER NOT NULL, etag TEXT, last_modified TEXT, PRIMARY KEY(source_key))")
   }
  }
  val MIGRATION_4_5: Migration = object : Migration(4, 5) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("CREATE TABLE IF NOT EXISTS threat_feed_staging (import_id TEXT NOT NULL, indicator_key TEXT NOT NULL, sha256_hash TEXT, md5_hash TEXT, ioc_value TEXT, ioc_type TEXT, threat_name TEXT NOT NULL, source TEXT NOT NULL, first_seen_at INTEGER, last_seen_at INTEGER, updated_at INTEGER NOT NULL, staged_at INTEGER NOT NULL, PRIMARY KEY(import_id, indicator_key))")
   }
  }
 }
}
