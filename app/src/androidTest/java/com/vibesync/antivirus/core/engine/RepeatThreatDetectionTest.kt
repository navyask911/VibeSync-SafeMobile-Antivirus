package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.local.ThreatSignature
import com.vibesync.antivirus.data.local.WhiteListEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class RepeatThreatDetectionTest {
    @Test fun sameValidApkIsDetectedAgainEvenAfterAnAllowlistEntry() = runBlocking {
        withContext(Dispatchers.IO) {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java).build()
            // The app's own valid test build is harmless; mark its copied hash only in an isolated DB.
            val apk = File.createTempFile("repeat-detection-", ".apk", context.cacheDir)
            try {
                File(context.applicationInfo.sourceDir).copyTo(apk, overwrite = true)
                val store = EncryptedHashStore(context)
                val encrypted = store.protectHash(HashCalculator().calculate(apk).sha256)
                database.threatDao().upsertSignatures(listOf(ThreatSignature(hash = encrypted,
                    malwareFamily = "HarmlessRepeatFixture", threatLevel = "test", dateAdded = System.currentTimeMillis())))
                val scanner = PackageScanner(context, database.threatDao(), store)
                val first = scanner.scanFile(apk)
                assertEquals(ScanVerdict.THREAT, first.verdict)
                database.threatDao().upsertWhitelistEntry(WhiteListEntry(hash = encrypted,
                    packageName = null, certifiedBy = "Prior user choice"))
                val second = scanner.scanFile(apk)
                assertEquals(ScanVerdict.THREAT, second.verdict)
                assertFalse(first.threatEventId.isNullOrBlank())
                assertNotEquals(first.threatEventId, second.threatEventId)
            } finally { apk.delete(); database.close() }
        }
    }
}
