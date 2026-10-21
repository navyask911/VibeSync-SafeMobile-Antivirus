package com.vibesync.antivirus.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

@Database(entities = [ThreatSignature::class, ScanAudit::class, WhiteListEntry::class], version = 2, exportSchema = false)
abstract class ThreatDatabase : RoomDatabase() {
 abstract fun threatDao(): ThreatDao

 companion object {
  /** Additive migration preserves all existing scan-audit rows. */
  val MIGRATION_1_2: Migration = object : Migration(1, 2) {
   override fun migrate(database: SupportSQLiteDatabase) {
    database.execSQL("ALTER TABLE scan_audits ADD COLUMN scan_session_id TEXT NOT NULL DEFAULT ''")
    database.execSQL("CREATE INDEX IF NOT EXISTS index_scan_audits_scan_session_id ON scan_audits(scan_session_id)")
   }
  }
 }
}