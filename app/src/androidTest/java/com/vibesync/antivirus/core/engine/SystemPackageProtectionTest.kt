package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.core.crypto.HashCalculator
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.local.ThreatSignature
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class SystemPackageProtectionTest {
    @Test fun systemPackageIsExcludedEvenWithAnExactLocalHashEntry() = runBlocking {
        withContext(Dispatchers.IO) {
            val context = ApplicationProvider.getApplicationContext<Context>()
            val database = Room.inMemoryDatabaseBuilder(context, ThreatDatabase::class.java).build()
            try {
                @Suppress("DEPRECATION")
                val info = context.packageManager.getApplicationInfo("com.android.settings", 0)
                val store = EncryptedHashStore(context)
                val hash = store.protectHash(HashCalculator().calculate(File(info.sourceDir)).sha256)
                database.threatDao().upsertSignatures(listOf(ThreatSignature(hash = hash,
                    malwareFamily = "HarmlessSystemExclusionFixture", threatLevel = "test", dateAdded = System.currentTimeMillis())))
                val scanner = PackageScanner(context, database.threatDao(), store)
                assertNull(scanner.scanInstalledPackage(info.packageName))
                assertNull(scanner.scanInstalledPackage("com.google.fixture"))
            } finally { database.close() }
        }
    }

    @Test fun sentinelAndReviewListsExcludeInstalledSystemResultsButRetainRawFileThreats() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<SafeMobileApp>()
        val installed = ScanResult("com.android.settings", "Settings", null, null, ScanVerdict.THREAT,
            emptyList(), 0, packageName = "com.android.settings")
        assertFalse(app.repository.isReviewableResult(installed))
        // A download's filename is not a trusted installed identity or a proof of its signer.
        assertTrue(app.repository.isReviewableResult(installed.copy(packageName = null,
            packageOrPath = "com.google.android.gms.apk", sourceUri = "content://fixture/file")))
    }
}
