package com.vibesync.antivirus.data.local
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

@Entity(tableName = "whitelist_entries", indices = [Index(value = ["hash"], unique = true)])
data class WhiteListEntry(
 @PrimaryKey(autoGenerate = true) val id: Long = 0,
 @ColumnInfo(name = "hash") val hash: String,
 @ColumnInfo(name = "package_name") val packageName: String?,
 @ColumnInfo(name = "certified_by") val certifiedBy: String
)
