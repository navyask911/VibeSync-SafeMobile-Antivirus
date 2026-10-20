package com.vibesync.antivirus.data.local
import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/** Stored hash is deterministic AES-SIV ciphertext, not the clear SHA-256. */
@Entity(tableName = "threat_signatures", indices = [Index(value = ["hash"], unique = true), Index(value = ["malware_family"])])
data class ThreatSignature(
 @PrimaryKey(autoGenerate = true) val id: Long = 0,
 @ColumnInfo(name = "hash") val hash: String,
 @ColumnInfo(name = "malware_family") val malwareFamily: String,
 @ColumnInfo(name = "threat_level") val threatLevel: String,
 @ColumnInfo(name = "date_added") val dateAdded: Long
)
