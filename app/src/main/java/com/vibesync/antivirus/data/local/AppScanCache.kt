package com.vibesync.antivirus.data.local

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/** Cached installed-package scan result, invalidated by update time or APK file size. */
@Entity(tableName = "app_scan_cache")
data class AppScanCache(
    @PrimaryKey
    @ColumnInfo(name = "packageName")
    val packageName: String,
    @ColumnInfo(name = "lastUpdateTime")
    val lastUpdateTime: Long,
    @ColumnInfo(name = "fileSize")
    val fileSize: Long,
    @ColumnInfo(name = "sha256")
    val sha256: String,
    @ColumnInfo(name = "verdict")
    val verdict: String,
    @ColumnInfo(name = "threatName")
    val threatName: String?
)
