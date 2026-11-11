package com.vibesync.antivirus.data.local

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "threat_feed_sync_state")
data class ThreatFeedSyncStateEntity(
    @PrimaryKey @ColumnInfo(name = "source_key") val sourceKey: String,
    @ColumnInfo(name = "source_host") val sourceHost: String,
    @ColumnInfo(name = "last_attempt_at") val lastAttemptAt: Long,
    @ColumnInfo(name = "last_success_at") val lastSuccessAt: Long? = null,
    @ColumnInfo(name = "status") val status: String,
    @ColumnInfo(name = "last_error") val lastError: String? = null,
    @ColumnInfo(name = "last_imported_count") val lastImportedCount: Int = 0,
    @ColumnInfo(name = "etag") val etag: String? = null,
    @ColumnInfo(name = "last_modified") val lastModified: String? = null,
    @ColumnInfo(name = "feed_version", defaultValue = "0") val feedVersion: Long = 0L,
    @ColumnInfo(name = "feed_manifest_sha256") val feedManifestSha256: String? = null
)
