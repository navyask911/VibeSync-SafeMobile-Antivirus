package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.io.File
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DrebinSchemaInstrumentedTest {
    @Test fun bundledSchemaHasExact215FeaturesAndModelRemainsResearchOnly() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val names = DrebinFeatureContract.loadSchema(app.assets)
        assertNotNull(names)
        assertEquals(215, names!!.size)
        assertEquals("transact", names[0])
        assertEquals("SEND_SMS", names[6])
        assertEquals("WRITE_SECURE_SETTINGS", names[214])
        val scanner = MachineLearningScanner(app)
        assertFalse("Research candidate must not pass production readiness.", scanner.isAvailable())
        assertTrue("Pinned research bundle remains available for controlled validation.",
            scanner.isResearchCandidateAvailable())
        assertEquals(0.5f, MachineLearningScanner.THRESHOLD, 0.0f)
    }

    @Test fun malformedApkReportsUnscannableAndNeverCrashes() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val file = File.createTempFile("unscannable-", ".apk", app.cacheDir)
        try {
            file.writeBytes(byteArrayOf(0x50, 0x4b, 0x03, 0x04))
            val result = MachineLearningScanner(app).extractFeatureVector(file)
            assertTrue(result is DrebinApkExtractor.Outcome.Unscannable)
        } finally {
            file.delete()
        }
    }

    @Test fun installedBaseAndSplitApksContributeToOne215FeatureVector() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val schema = requireNotNull(DrebinFeatureContract.loadSchema(app.assets))
        val root = File(app.cacheDir, "drebin-split-fixture-${System.nanoTime()}")
        check(root.mkdirs())
        val base = File(root, "base.apk")
        val split = File(root, "feature.apk")
        try {
            writeFixtureApk(base, manifest = createBinaryManifestFixture(
                permission = "android.permission.INTERNET"
            ), dex = createEmptyDexFixture())
            writeFixtureApk(split, manifest = createBinaryManifestFixture(
                action = "android.intent.action.BOOT_COMPLETED"
            ), dex = createEmptyDexFixture())
            val baseOnly = DrebinApkExtractor.extract(base, schema)
            val packageResult = DrebinApkExtractor.extract(listOf(base, split), schema)
            assertTrue(baseOnly is DrebinApkExtractor.Outcome.Features)
            assertTrue(packageResult is DrebinApkExtractor.Outcome.Features)
            val baseVector = (baseOnly as DrebinApkExtractor.Outcome.Features).vector
            val combined = packageResult as DrebinApkExtractor.Outcome.Features
            assertEquals(2, combined.apkCount)
            assertEquals(2, combined.dexCount)
            assertEquals(1f, baseVector[schema.indexOf("INTERNET")], 0f)
            assertEquals(0f, baseVector[schema.indexOf("android.intent.action.BOOT_COMPLETED")], 0f)
            assertEquals(1f, combined.vector[schema.indexOf("INTERNET")], 0f)
            assertEquals(1f, combined.vector[schema.indexOf("android.intent.action.BOOT_COMPLETED")], 0f)
        } finally {
            base.delete()
            split.delete()
            root.delete()
        }
    }

    @Test fun dexPresentOnlyInFeatureSplitStillProducesCompleteExtraction() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val schema = requireNotNull(DrebinFeatureContract.loadSchema(app.assets))
        val root = File(app.cacheDir, "drebin-split-dex-fixture-${System.nanoTime()}")
        check(root.mkdirs())
        val base = File(root, "base.apk")
        val split = File(root, "dex-feature.apk")
        try {
            writeFixtureApk(base, manifest = createBinaryManifestFixture(
                permission = "android.permission.INTERNET"
            ), dex = null)
            writeFixtureApk(split, manifest = createBinaryManifestFixture(
                action = "android.intent.action.BOOT_COMPLETED"
            ), dex = createEmptyDexFixture())
            val baseOnly = DrebinApkExtractor.extract(base, schema)
            assertTrue(baseOnly is DrebinApkExtractor.Outcome.Unscannable)
            assertEquals(DrebinApkExtractor.Reason.DEX_MISSING,
                (baseOnly as DrebinApkExtractor.Outcome.Unscannable).reason)
            val combined = DrebinApkExtractor.extract(listOf(base, split), schema)
            assertTrue(combined is DrebinApkExtractor.Outcome.Features)
            assertEquals(1, (combined as DrebinApkExtractor.Outcome.Features).dexCount)
            assertEquals(1f, combined.vector[schema.indexOf("INTERNET")], 0f)
            assertEquals(1f, combined.vector[schema.indexOf("android.intent.action.BOOT_COMPLETED")], 0f)
        } finally {
            base.delete()
            split.delete()
            root.delete()
        }
    }

    @Test fun successfullyParsedNoMatchApkIsValidAllZeroNotAnExtractionFailure() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val schema = requireNotNull(DrebinFeatureContract.loadSchema(app.assets))
        val apk = File.createTempFile("drebin-zero-match-", ".apk", app.cacheDir)
        try {
            writeFixtureApk(apk, manifest = createBinaryManifestFixture(), dex = createEmptyDexFixture())
            val outcome = DrebinApkExtractor.extract(apk, schema)
            assertTrue(outcome is DrebinApkExtractor.Outcome.Features)
            val vector = (outcome as DrebinApkExtractor.Outcome.Features).vector
            assertEquals(215, vector.size)
            assertTrue("A valid parse with no matched signals may legitimately be all zero.",
                vector.all { it == 0f })
        } finally {
            apk.delete()
        }
    }

    @Test fun unreadableCorruptAndPartiallyParsedSplitSetsFailClosed() = runBlocking {
        val app = ApplicationProvider.getApplicationContext<Context>()
        val schema = requireNotNull(DrebinFeatureContract.loadSchema(app.assets))
        val missing = File(app.cacheDir, "does-not-exist-${System.nanoTime()}.apk")
        val missingOutcome = DrebinApkExtractor.extract(missing, schema)
        assertTrue(missingOutcome is DrebinApkExtractor.Outcome.Unscannable)
        assertEquals(DrebinApkExtractor.Reason.UNREADABLE_APK,
            (missingOutcome as DrebinApkExtractor.Outcome.Unscannable).reason)

        val root = File(app.cacheDir, "drebin-bad-split-fixture-${System.nanoTime()}")
        check(root.mkdirs())
        val base = File(root, "base.apk")
        val corruptSplit = File(root, "bad-split.apk")
        val malformedDex = File(root, "bad-dex.apk")
        try {
            writeFixtureApk(base, manifest = createBinaryManifestFixture(), dex = createEmptyDexFixture())
            corruptSplit.writeBytes("broken zip content".toByteArray())
            val partial = DrebinApkExtractor.extract(listOf(base, corruptSplit), schema)
            assertTrue(partial is DrebinApkExtractor.Outcome.Unscannable)
            assertEquals(DrebinApkExtractor.Reason.APK_INVALID,
                (partial as DrebinApkExtractor.Outcome.Unscannable).reason)

            writeFixtureApk(malformedDex, manifest = createBinaryManifestFixture(), dex = ByteArray(64))
            val invalidDex = DrebinApkExtractor.extract(malformedDex, schema)
            assertTrue(invalidDex is DrebinApkExtractor.Outcome.Unscannable)
            assertEquals(DrebinApkExtractor.Reason.DEX_INVALID,
                (invalidDex as DrebinApkExtractor.Outcome.Unscannable).reason)

            writeFixtureApk(malformedDex, manifest = null, dex = createEmptyDexFixture())
            val missingManifest = DrebinApkExtractor.extract(malformedDex, schema)
            assertTrue(missingManifest is DrebinApkExtractor.Outcome.Unscannable)
            assertEquals(DrebinApkExtractor.Reason.MANIFEST_INVALID,
                (missingManifest as DrebinApkExtractor.Outcome.Unscannable).reason)
        } finally {
            base.delete()
            corruptSplit.delete()
            malformedDex.delete()
            root.delete()
        }
    }

    private fun writeFixtureApk(file: File, manifest: ByteArray?, dex: ByteArray?) {
        ZipOutputStream(file.outputStream().buffered()).use { zip ->
            if (manifest != null) {
                zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
                zip.write(manifest)
                zip.closeEntry()
            }
            if (dex != null) {
                zip.putNextEntry(ZipEntry("classes.dex"))
                zip.write(dex)
                zip.closeEntry()
            }
        }
    }

    private fun createEmptyDexFixture(): ByteArray {
        val bytes = ByteBuffer.allocate(140).order(ByteOrder.LITTLE_ENDIAN)
        bytes.put(byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00))
        bytes.position(32)
        bytes.putInt(140) // file_size
        bytes.putInt(112) // header_size
        bytes.putInt(0x12345678) // endian_tag
        bytes.putInt(0) // link_size
        bytes.putInt(0) // link_off
        bytes.putInt(112) // map_off
        repeat(12) { bytes.putInt(0) } // six empty ID tables
        bytes.putInt(28) // data_size (map_list)
        bytes.putInt(112) // data_off
        bytes.putInt(2) // map_list size
        bytes.putShort(0x0000.toShort()).putShort(0).putInt(1).putInt(0) // header item
        bytes.putShort(0x1000.toShort()).putShort(0).putInt(1).putInt(112) // map_list item
        val result = bytes.array()
        val signature = MessageDigest.getInstance("SHA-1").digest(result.copyOfRange(32, result.size))
        System.arraycopy(signature, 0, result, 12, signature.size)
        val checksum = Adler32().apply { update(result, 12, result.size - 12) }.value.toInt()
        ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).putInt(8, checksum)
        return result
    }

    private fun createBinaryManifestFixture(
        permission: String? = null,
        action: String? = null
    ): ByteArray {
        data class Element(val tag: String, val value: String?)
        val elements = buildList {
            if (permission != null) add(Element("uses-permission", permission))
            if (action != null) add(Element("action", action))
            if (isEmpty()) add(Element("application", null))
        }
        val strings = elements.flatMap {
            listOfNotNull(it.tag, if (it.value != null) "name" else null, it.value)
        }.distinct()
        val stringData = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        for (value in strings) {
            val encoded = value.toByteArray(Charsets.UTF_8)
            require(encoded.size < 128 && value.length < 128)
            offsets += stringData.size()
            stringData.write(value.length)
            stringData.write(encoded.size)
            stringData.write(encoded)
            stringData.write(0)
        }
        val stringsStart = 28 + offsets.size * 4
        val unpaddedPoolSize = stringsStart + stringData.size()
        val padding = (4 - unpaddedPoolSize % 4) % 4
        repeat(padding) { stringData.write(0) }
        val poolSize = stringsStart + stringData.size()
        val pool = ByteBuffer.allocate(poolSize).order(ByteOrder.LITTLE_ENDIAN)
        pool.putShort(0x0001.toShort()).putShort(28.toShort()).putInt(poolSize)
        pool.putInt(strings.size).putInt(0).putInt(0x100).putInt(stringsStart).putInt(0)
        offsets.forEach(pool::putInt)
        pool.put(stringData.toByteArray())

        fun startElement(element: Element): ByteArray {
            val hasAttribute = element.value != null
            val node = ByteBuffer.allocate(if (hasAttribute) 56 else 36).order(ByteOrder.LITTLE_ENDIAN)
            node.putShort(0x0102.toShort()).putShort(36.toShort()).putInt(node.capacity())
            node.putInt(1).putInt(-1).putInt(-1).putInt(strings.indexOf(element.tag))
            node.putShort(20.toShort()).putShort(20.toShort())
            node.putShort(if (hasAttribute) 1.toShort() else 0.toShort())
            node.putShort(0).putShort(0).putShort(0)
            if (hasAttribute) {
                val valueIndex = strings.indexOf(element.value)
                node.putInt(-1).putInt(strings.indexOf("name")).putInt(valueIndex)
                node.putShort(8.toShort()).put(0.toByte()).put(0x03.toByte()).putInt(valueIndex)
            }
            return node.array()
        }

        val nodes = elements.map(::startElement)
        val totalSize = 8 + poolSize + nodes.sumOf { it.size }
        val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            .putShort(0x0003.toShort()).putShort(8.toShort()).putInt(totalSize).array()
        return ByteArray(totalSize).also { output ->
            var offset = 0
            (listOf(header, pool.array()) + nodes).forEach { chunk ->
                chunk.copyInto(output, offset)
                offset += chunk.size
            }
        }
    }

}
