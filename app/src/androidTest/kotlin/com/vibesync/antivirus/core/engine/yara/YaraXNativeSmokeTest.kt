package com.vibesync.antivirus.core.engine.yara

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class YaraXNativeSmokeTest {

    @Test
    fun bundledPlaceholderCompilesAndScansApkManifestAndDex() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val apk = File.createTempFile("yarax-native-smoke-", ".apk", context.cacheDir)
        val scanner = YaraScanner(context)

        try {
            ZipOutputStream(FileOutputStream(apk)).use { zip ->
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(byteArrayOf(0x03, 0x00, 0x08, 0x00))
                zip.closeEntry()

                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(
                    "SAFEMOBILE_YARAX_PLACEHOLDER_MATCH_ONLY".toByteArray(Charsets.US_ASCII)
                )
                zip.closeEntry()
            }

            val result = scanner.scanApk(apk)

            assertEquals(YaraXScanState.MATCHES, result.state)
            assertTrue(result.matches.any { it.ruleIdentifier == "SafeMobile_YaraX_Integration_Placeholder" })
            assertFalse("Placeholder metadata must not claim malware.", result.threatMatches.isNotEmpty())
            assertFalse("Placeholder metadata must not be suspicious.", result.suspiciousMatches.isNotEmpty())
            assertTrue(result.matches.any { it.componentName == "classes.dex" })
        } finally {
            scanner.close()
            apk.delete()
        }
    }
}
