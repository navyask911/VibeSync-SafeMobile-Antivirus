package com.vibesync.antivirus.core.quarantine

import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Result of deleting a quarantined file and then removing its local index record. */
internal enum class QuarantineDeleteOutcome {
    DELETED,
    FILE_NOT_FOUND,
    ACCESS_DENIED,
    FAILED
}

/**
 * Coordinates the two persistent stores conservatively.
 * Filesystem deletion and a Room transaction cannot form one ACID transaction. The file is
 * deleted first; its Room row is removed only after successful deletion. If deletion fails,
 * the Room record is retained. The Room callback itself should use a transaction.
 */
internal class QuarantineDeleteOperation(
    private val deletePayload: (File) -> Boolean,
    private val deleteRoomEntry: suspend (String) -> Unit,
    private val exists: (File) -> Boolean = { it.exists() }
) {
    suspend fun delete(file: File): QuarantineDeleteOutcome = withContext(Dispatchers.IO) {
        try {
            if (!exists(file)) return@withContext QuarantineDeleteOutcome.FILE_NOT_FOUND
            if (!deletePayload(file)) return@withContext QuarantineDeleteOutcome.FAILED
            deleteRoomEntry(file.name)
            QuarantineDeleteOutcome.DELETED
        } catch (_: SecurityException) {
            QuarantineDeleteOutcome.ACCESS_DENIED
        } catch (_: Exception) {
            QuarantineDeleteOutcome.FAILED
        }
    }
}
