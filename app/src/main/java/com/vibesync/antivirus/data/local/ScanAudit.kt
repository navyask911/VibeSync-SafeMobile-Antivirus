package com.vibesync.antivirus.data.local
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "scan_audits", indices = [Index(value = ["scan_timestamp"]), Index(value = ["verdict"])])
data class ScanAudit(
 @PrimaryKey(autoGenerate = true) val id: Long = 0,
 @ColumnInfo(name = "package_or_path") val packageOrPath: String,
 @ColumnInfo(name = "hash") val hash: String,
 @ColumnInfo(name = "scan_timestamp") val scanTimestamp: Long,
 @ColumnInfo(name = "verdict") val verdict: String,
 @ColumnInfo(name = "scan_duration") val scanDuration: Long
)
