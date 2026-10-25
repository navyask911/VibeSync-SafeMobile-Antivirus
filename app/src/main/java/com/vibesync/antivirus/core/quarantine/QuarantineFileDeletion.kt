package com.vibesync.antivirus.core.quarantine

import java.io.File

/** Returns true only when an existing payload was successfully deleted. */
internal object QuarantineFileDeletion {
    fun delete(
        file: File,
        exists: (File) -> Boolean = { it.exists() },
        delete: (File) -> Boolean = { it.delete() }
    ): Boolean = try {
        exists(file) && delete(file)
    } catch (_: SecurityException) {
        false
    } catch (_: java.io.IOException) {
        false
    }
}
