package com.vibesync.antivirus.data.local

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Minimal local event record. Accessibility dumps and unrelated screen content are never stored. */
@Entity(
    tableName = "security_incidents",
    indices = [Index(value = ["occurred_at"]), Index(value = ["sha256_hash"])]
)
data class SecurityIncidentEntity(
    @PrimaryKey @ColumnInfo(name = "event_id") val eventId: String,
    @ColumnInfo(name = "occurred_at") val occurredAt: Long,
    @ColumnInfo(name = "event_kind") val eventKind: String,
    @ColumnInfo(name = "installer_package") val installerPackage: String? = null,
    @ColumnInfo(name = "source_package") val sourcePackage: String? = null,
    @ColumnInfo(name = "filename") val filename: String? = null,
    @ColumnInfo(name = "sha256_hash") val sha256Hash: String? = null,
    @ColumnInfo(name = "original_path") val originalPath: String? = null,
    @ColumnInfo(name = "reason") val reason: String,
    @ColumnInfo(name = "action_taken") val actionTaken: String,
    @ColumnInfo(name = "status") val status: String
)
