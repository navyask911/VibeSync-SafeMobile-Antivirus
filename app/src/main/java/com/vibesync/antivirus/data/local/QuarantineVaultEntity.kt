package com.vibesync.antivirus.data.local

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Room index for items in the app-private encrypted Quarantine Vault. */
@Entity(
    tableName = "quarantine_vault_entries",
    indices = [Index(value = ["created_at"]), Index(value = ["sha256_hash"]), Index(value = ["status"])]
)
data class QuarantineVaultEntity(
    @PrimaryKey @ColumnInfo(name = "vault_id") val vaultId: String,
    @ColumnInfo(name = "created_at") val createdAt: Long,
    @ColumnInfo(name = "original_filename") val originalFilename: String,
    @ColumnInfo(name = "original_path") val originalPath: String,
    @ColumnInfo(name = "sha256_hash") val sha256Hash: String?,
    @ColumnInfo(name = "source_package") val sourcePackage: String?,
    @ColumnInfo(name = "quarantined_path") val quarantinedPath: String,
    @ColumnInfo(name = "detection_reason") val detectionReason: String,
    @ColumnInfo(name = "status") val status: String
)
