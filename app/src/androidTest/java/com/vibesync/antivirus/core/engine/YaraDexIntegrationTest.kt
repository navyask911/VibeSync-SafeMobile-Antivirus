package com.vibesync.antivirus.core.engine

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

@RunWith(AndroidJUnit4::class)
class YaraDexIntegrationTest {
    @Test fun extractedDexProducesAdvisoryRuleFindingWithoutExternalNetwork() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        BundledYaraEngine.initialize(context.assets)
        assertTrue(BundledYaraEngine.capability.active)
        assertEquals(5, BundledYaraEngine.capability.ruleCount)
        val apk = File.createTempFile("dex-yara-synthetic-", ".apk", context.cacheDir)
        try {
            val dex = ByteArray(512)
            val magic = "dex\n035\u0000".toByteArray(StandardCharsets.ISO_8859_1)
            System.arraycopy(magic, 0, dex, 0, magic.size)
            val markers = "AccessibilityService onAccessibilityEvent WindowManager SMS_RECEIVED"
                .toByteArray(StandardCharsets.US_ASCII)
            System.arraycopy(markers, 0, dex, 128, markers.size)
            ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(32, dex.size).putInt(36, 0x70).putInt(40, 0x12345678)
            ZipOutputStream(apk.outputStream()).use { out ->
                out.putNextEntry(ZipEntry("classes.dex"))
                out.write(dex)
                out.closeEntry()
            }
            val report = DeepStaticAnalyzer().analyze(null, apk)
            assertEquals(YaraScanState.MATCHES, report.yaraResult?.state)
            assertTrue(report.findings.any {
                it.ruleId == "YARA_Takopii_Overlay_Banker_DEX" &&
                    it.evidence.contains("classes.dex") && it.evidence.contains("AccessibilityService")
            })
            assertTrue(report.isSuspicious)
        } finally { apk.delete() }
    }
}
