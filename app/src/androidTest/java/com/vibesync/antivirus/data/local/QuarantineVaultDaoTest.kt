package com.vibesync.antivirus.data.local

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import android.content.Context
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import androidx.test.ext.junit.runners.AndroidJUnit4

@RunWith(AndroidJUnit4::class)
class QuarantineVaultDaoTest {
    private lateinit var database: ThreatDatabase
    @Before fun setUp() {
        database = Room.inMemoryDatabaseBuilder(
            ApplicationProvider.getApplicationContext<Context>(),
            ThreatDatabase::class.java
        ).build()
    }
    @After fun tearDown() { database.close() }

    @Test fun persistsAndListsQuarantineMetadata() = runBlocking {
        val row = QuarantineVaultEntity(
            vaultId = "vault-id", createdAt = 1234L, originalFilename = "sample.apk",
            originalPath = "Downloads/sample.apk", sha256Hash = "a".repeat(64),
            sourcePackage = null, quarantinedPath = "/app-private/quarantine/encrypted.smq",
            detectionReason = "local_sha256_match", status = "QUARANTINED"
        )
        database.quarantineVaultDao().insert(row)
        assertEquals(row, database.quarantineVaultDao().findById("vault-id"))
        assertEquals(listOf(row), database.quarantineVaultDao().listRecent(10))
    }
}
