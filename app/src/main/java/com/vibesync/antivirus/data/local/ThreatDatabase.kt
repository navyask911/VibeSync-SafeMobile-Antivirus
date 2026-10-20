package com.vibesync.antivirus.data.local
import androidx.room.Database
import androidx.room.RoomDatabase

@Database(entities = [ThreatSignature::class, ScanAudit::class, WhiteListEntry::class], version = 1, exportSchema = false)
abstract class ThreatDatabase : RoomDatabase() {
 abstract fun threatDao(): ThreatDao
}
