package com.vibesync.antivirus.core.engine

/**
 * Scalar-only installed-package presentation data.
 * Android PackageManager and graphics objects must never be stored here.
 */
data class InstalledAppItem(
    val packageName: String,
    val appLabel: String,
    val verdict: String = "NOT_SCANNED",
    val fileSize: Long = 0L,
    val isSystem: Boolean = false
)
