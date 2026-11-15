package com.vibesync.antivirus.data.local
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index

/** Completed work ledger; stable item keys support resume after process death. */
@Entity(tableName = "scan_session_items", primaryKeys = ["session_id", "item_key"],
 indices = [Index(value = ["session_id"]), Index(value = ["completed_at"])])
data class ScanSessionItemEntity(
 @ColumnInfo(name = "session_id") val sessionId: String,
 @ColumnInfo(name = "item_key") val itemKey: String,
 @ColumnInfo(name = "item_type") val itemType: String,
 @ColumnInfo(name = "item_path") val itemPath: String,
 @ColumnInfo(name = "verdict") val verdict: String,
 @ColumnInfo(name = "package_name") val packageName: String? = null,
 @ColumnInfo(name = "sha256_hash") val sha256Hash: String? = null,
 @ColumnInfo(name = "md5_hash") val md5Hash: String? = null,
 @ColumnInfo(name = "reasons") val reasons: String = "",
 @ColumnInfo(name = "risk_score") val riskScore: Float = 0f,
 @ColumnInfo(name = "detection_source") val detectionSource: String = "NONE",
 @ColumnInfo(name = "malware_name") val malwareName: String? = null,
 @ColumnInfo(name = "threat_event_id") val threatEventId: String? = null,
 @ColumnInfo(name = "duration_ms") val durationMs: Long = 0L,
 @ColumnInfo(name = "source_uri") val sourceUri: String? = null,
 @ColumnInfo(name = "completed_at") val completedAt: Long
)
