package com.vibesync.antivirus.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(
 entities = [ThreatSignature::class, ScanAudit::class, WhiteListEntry::class, MalwareHashEntity::class, ThreatFeedSyncStateEntity::class, ThreatFeedStagingEntity::class, SecurityIncidentEntity::class, QuarantineVaultEntity::class],
 version = 8, exportSchema = false
)
abstract class ThreatDatabase : RoomDatabase() {
 abstract fun threatDao(): ThreatDao
 abstract fun malwareHashDao(): MalwareHashDao
 abstract fun threatFeedSyncStateDao(): ThreatFeedSyncStateDao
 abstract fun threatFeedStagingDao(): ThreatFeedStagingDao
 abstract fun securityIncidentDao(): SecurityIncidentDao
 abstract fun quarantineVaultDao(): QuarantineVaultDao

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
  val MIGRATION_5_6: Migration = object : Migration(5, 6) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("CREATE TABLE IF NOT EXISTS security_incidents (event_id TEXT NOT NULL, occurred_at INTEGER NOT NULL, event_kind TEXT NOT NULL, installer_package TEXT, source_package TEXT, filename TEXT, sha256_hash TEXT, original_path TEXT, reason TEXT NOT NULL, action_taken TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(event_id))")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_security_incidents_occurred_at ON security_incidents(occurred_at)")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_security_incidents_sha256_hash ON security_incidents(sha256_hash)")
   }
  }
  val MIGRATION_6_7: Migration = object : Migration(6, 7) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("CREATE TABLE IF NOT EXISTS quarantine_vault_entries (vault_id TEXT NOT NULL, created_at INTEGER NOT NULL, original_filename TEXT NOT NULL, original_path TEXT NOT NULL, sha256_hash TEXT, source_package TEXT, quarantined_path TEXT NOT NULL, detection_reason TEXT NOT NULL, status TEXT NOT NULL, PRIMARY KEY(vault_id))")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_quarantine_vault_entries_created_at ON quarantine_vault_entries(created_at)")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_quarantine_vault_entries_sha256_hash ON quarantine_vault_entries(sha256_hash)")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_quarantine_vault_entries_status ON quarantine_vault_entries(status)")
   }
  }
  val MIGRATION_7_8: Migration = object : Migration(7, 8) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("ALTER TABLE threat_feed_sync_state ADD COLUMN feed_version INTEGER NOT NULL DEFAULT 0")
    database.execSQL("ALTER TABLE threat_feed_sync_state ADD COLUMN feed_manifest_sha256 TEXT")
   }
  }
 }
}
