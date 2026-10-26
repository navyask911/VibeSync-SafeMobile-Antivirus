package com.vibesync.antivirus.core.quarantine

import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuarantineDeleteOperationTest {
    @Test
    fun failedPayloadDeletionNeverDeletesItsRoomRecord() = runBlocking {
        var rowDeleted = false
        val operation = QuarantineDeleteOperation(deletePayload = { false },
            deleteRoomEntry = { rowDeleted = true }, exists = { true })
        assertEquals(QuarantineDeleteOutcome.FAILED, operation.delete(File("locked.smq")))
        assertFalse(rowDeleted)
    }

    @Test
    fun disappearingFileIsReportedWithoutDeletingTheRoomRecord() = runBlocking {
        var rowDeleted = false
        val operation = QuarantineDeleteOperation(deletePayload = { throw java.io.FileNotFoundException() },
            deleteRoomEntry = { rowDeleted = true }, exists = { true })
        assertEquals(QuarantineDeleteOutcome.FILE_NOT_FOUND, operation.delete(File("gone.smq")))
        assertFalse(rowDeleted)
    }

    @Test
    fun roomFailureIsReportedAndCancellationRemainsCancellation() = runBlocking {
        val operation = QuarantineDeleteOperation(deletePayload = { true },
            deleteRoomEntry = { throw IllegalStateException("Room unavailable") }, exists = { true })
        assertEquals(QuarantineDeleteOutcome.FAILED, operation.delete(File("payload.smq")))
        val cancelled = QuarantineDeleteOperation(deletePayload = { true },
            deleteRoomEntry = { throw kotlinx.coroutines.CancellationException("cancelled") }, exists = { true })
        try {
            cancelled.delete(File("payload.smq"))
            org.junit.Assert.fail("Cancellation must propagate")
        } catch (_: kotlinx.coroutines.CancellationException) { }
    }

    @Test
    fun deleteSuccessRemovesFileAndRoomRecord() = runBlocking {
        val file = File.createTempFile("quarantine-delete", ".encrypted")
        file.writeText("encrypted-test-content")
        val removedRows = mutableListOf<String>()
        try {
            val operation = QuarantineDeleteOperation(
                deletePayload = { it.delete() },
                deleteRoomEntry = { removedRows += it }
            )
            assertEquals(QuarantineDeleteOutcome.DELETED, operation.delete(file))
            assertFalse(file.exists())
            assertEquals(listOf(file.name), removedRows)
        } finally {
            file.delete()
        }
    }

    @Test
    fun missingFileLeavesRoomRecordUntouched() = runBlocking {
        val file = File.createTempFile("quarantine-missing", ".encrypted")
        file.delete()
        val removedRows = mutableListOf<String>()
        val operation = QuarantineDeleteOperation(
            deletePayload = { it.delete() },
            deleteRoomEntry = { removedRows += it }
        )
        assertEquals(QuarantineDeleteOutcome.FILE_NOT_FOUND, operation.delete(file))
        assertTrue(removedRows.isEmpty())
    }

    @Test
    fun securityExceptionLeavesRoomRecordUntouched() = runBlocking {
        val file = File.createTempFile("quarantine-denied", ".encrypted")
        file.writeText("encrypted-test-content")
        val removedRows = mutableListOf<String>()
        try {
            val operation = QuarantineDeleteOperation(
                deletePayload = { throw SecurityException("denied") },
                deleteRoomEntry = { removedRows += it }
            )
            assertEquals(QuarantineDeleteOutcome.ACCESS_DENIED, operation.delete(file))
            assertTrue(file.exists())
            assertTrue(removedRows.isEmpty())
        } finally {
            file.delete()
        }
    }
}

