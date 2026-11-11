package com.vibesync.antivirus.core.quarantine

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class QuarantineFileDeletionTest {
    @Test
    fun disappearingLockedAndUnexpectedStorageFailuresDoNotEscape() {
        for (error in listOf(java.io.FileNotFoundException(), java.io.IOException("locked"), IllegalStateException("storage"))) {
            assertFalse(QuarantineFileDeletion.delete(File("payload.smq"), exists = { true }, delete = { throw error }))
            assertFalse(QuarantineFileDeletion.delete(File("payload.smq"), exists = { throw error }))
        }
    }

    @Test
    fun fileSystemRefusalIsReturnedAsFailure() {
        assertFalse(QuarantineFileDeletion.delete(File("locked.smq"), exists = { true }, delete = { false }))
    }

    @Test
    fun deleteSucceedsForPresentPayload() {
        var deleteCalled = false
        val result = QuarantineFileDeletion.delete(
            file = File("payload.smq"),
            exists = { true },
            delete = { deleteCalled = true; true }
        )
        assertTrue(result)
        assertTrue(deleteCalled)
    }

    @Test
    fun missingPayloadIsNotDeleted() {
        var deleteCalled = false
        val result = QuarantineFileDeletion.delete(
            file = File("missing.smq"),
            exists = { false },
            delete = { deleteCalled = true; true }
        )
        assertFalse(result)
        assertFalse(deleteCalled)
    }

    @Test
    fun securityExceptionIsReturnedAsFailure() {
        val result = QuarantineFileDeletion.delete(
            file = File("denied.smq"),
            exists = { true },
            delete = { throw SecurityException("permission revoked") }
        )
        assertFalse(result)
    }
}

