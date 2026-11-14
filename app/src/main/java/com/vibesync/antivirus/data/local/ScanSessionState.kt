package com.vibesync.antivirus.data.local
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/** Durable progress and resume metadata for one foreground-service scan. */
@Entity(tableName = "scan_session_state")
data class ScanSessionState(
 @PrimaryKey @ColumnInfo(name = "session_id") val sessionId: String,
 @ColumnInfo(name = "total_items") val totalItems: Int = 0,
 @ColumnInfo(name = "scanned_items") val scannedItems: Int = 0,
 @ColumnInfo(name = "current_item_path") val currentItemPath: String? = null,
 @ColumnInfo(name = "scan_type") val scanType: String,
 @ColumnInfo(name = "is_complete") val isComplete: Boolean = false,
 @ColumnInfo(name = "operation_type") val operationType: String = "FULL_DEVICE",
 @ColumnInfo(name = "source_uri") val sourceUri: String? = null,
 @ColumnInfo(name = "package_name") val packageName: String? = null,
 @ColumnInfo(name = "is_manual") val isManual: Boolean = true
)
