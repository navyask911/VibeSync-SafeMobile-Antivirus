package com.vibesync.antivirus.core.engine

/**
 * Scalar-only installed-package inventory data, not a persisted scan verdict.
 * Android PackageManager and graphics objects must never be stored here.
 */
data class InstalledAppItem(
    val packageName: String,
    val appLabel: String,
    val verdict: String = INVENTORY_ONLY,
    val fileSize: Long = 0L,
    val isSystem: Boolean = false
) {
    companion object {
        const val INVENTORY_ONLY = "INVENTORY_ONLY"
    }
}
