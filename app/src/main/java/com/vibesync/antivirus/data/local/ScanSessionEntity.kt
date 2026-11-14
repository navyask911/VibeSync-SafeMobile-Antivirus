package com.vibesync.antivirus.data.local

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(
    tableName = "scan_sessions",
    indices = [Index(value = ["started_at"]), Index(value = ["status"])]
)
data class ScanSessionEntity(
    @PrimaryKey
    @ColumnInfo(name = "session_id")
    val sessionId: String,
    @ColumnInfo(name = "scan_type")
    val scanType: String,
    @ColumnInfo(name = "started_at")
    val startedAt: Long,
    @ColumnInfo(name = "completed_at")
    val completedAt: Long? = null,
    @ColumnInfo(name = "status")
    val status: String
) {
    companion object {
        const val IN_PROGRESS = "IN_PROGRESS"
        const val COMPLETED = "COMPLETED"
        const val INTERRUPTED = "INTERRUPTED"
    }
}
