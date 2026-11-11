package com.vibesync.antivirus.core.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.engine.ScanVerdict
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class TrustedAppStoreTest {
    @Test fun trustedApkWithRenamedExtensionSkipsFileAndStreamScanners() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = TrustedAppStore(context)
        val renamed = java.io.File.createTempFile("trusted-rename-", ".bin", context.cacheDir)
        try {
            java.io.File(context.applicationInfo.sourceDir).copyTo(renamed, overwrite = true)
            assertTrue(store.trust(context.packageName))
            val app = context as SafeMobileApp
            val fileResult = app.repository.scanFile(renamed)
            val scanner = com.vibesync.antivirus.core.engine.PackageScanner(context,
                app.database.threatDao(), com.vibesync.antivirus.core.crypto.EncryptedHashStore(context))
            val streamResult = scanner.scanStream("renamed.bin", renamed.inputStream())
            for (result in listOf(fileResult, streamResult)) {
                assertTrue(result.trustedByUser)
                assertEquals(ScanVerdict.NO_MATCH, result.verdict)
                assertNull(result.sha256)
                assertNull(result.md5)
                assertNull(result.riskReport)
                assertNull(result.threatEventId)
            }
        } finally {
            store.untrust(context.packageName)
            renamed.delete()
        }
    }

    @Test fun packageTrustBypassesAllEnginesWithoutReadingApkBytes() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val store = TrustedAppStore(context)
        val name = "com.example.safemobiletest.p" + UUID.randomUUID().toString().replace("-", "")
        try {
            assertFalse(store.isTrusted(name))
            assertTrue(store.trust(name))
            assertTrue(store.isTrusted(name))
            assertFalse(store.trust("invalid package"))
            // This package does not exist: returning before PackageManager lookup proves
            // neither APK hashing nor any subsequent detection engine can have executed.
            val result = (context as SafeMobileApp).repository.scanInstalledPackage(name)
            assertNotNull(result)
            assertEquals(ScanVerdict.NO_MATCH, result!!.verdict)
            assertTrue(result.trustedByUser)
            assertNull(result.sha256)
            assertNull(result.md5)
            assertNull(result.riskReport)
            assertNull(result.threatEventId)
            assertEquals(0f, result.riskScore)
        } finally { store.untrust(name) }
        assertFalse(store.isTrusted(name))
        assertNull((context as SafeMobileApp).repository.scanInstalledPackage(name))
    }
}
