package com.vibesync.antivirus.data.local

import androidx.room.ColumnInfo
import androidx.room.Entity

/**
 * Disk-backed per-run staging rows. Active indicators are not changed until the
 * entire feed has parsed and the staged set can be promoted atomically.
 */
@Entity(
    tableName = "threat_feed_staging",
    primaryKeys = ["import_id", "indicator_key"]
)
data class ThreatFeedStagingEntity(
    @ColumnInfo(name = "import_id") val importId: String,
    @ColumnInfo(name = "indicator_key") val indicatorKey: String,
    @ColumnInfo(name = "sha256_hash") val sha256Hash: String? = null,
    @ColumnInfo(name = "md5_hash") val md5Hash: String? = null,
    @ColumnInfo(name = "ioc_value") val iocValue: String? = null,
    @ColumnInfo(name = "ioc_type") val iocType: String? = null,
    @ColumnInfo(name = "threat_name") val threatName: String,
    @ColumnInfo(name = "source") val source: String,
    @ColumnInfo(name = "first_seen_at") val firstSeenAt: Long? = null,
    @ColumnInfo(name = "last_seen_at") val lastSeenAt: Long? = null,
    @ColumnInfo(name = "updated_at") val updatedAt: Long,
    @ColumnInfo(name = "staged_at") val stagedAt: Long
)
