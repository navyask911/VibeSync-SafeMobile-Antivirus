package com.vibesync.antivirus.core.engine.yara

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.util.zip.ZipInputStream

data class ApkComponent(
    val entryName: String,
    val bytes: ByteArray
)

sealed class ApkExtractionOutcome {
    data class Complete(val components: List<ApkComponent>) : ApkExtractionOutcome()
    data class Incomplete(val reason: String) : ApkExtractionOutcome()
}

/**
 * Streams the APK's local ZIP entries and buffers only the root binary manifest
 * and root DEX files for YARA-X. Non-target entries are drained and discarded;
 * no archive contents are written to disk.
 */
class ApkContentExtractor {

    suspend fun extract(apk: File): ApkExtractionOutcome = withContext(Dispatchers.IO) {
        if (!apk.isFile || !apk.canRead()) {
            return@withContext ApkExtractionOutcome.Incomplete("APK is not a readable file.")
        }
        if (apk.length() !in 1..MAX_APK_BYTES) {
            return@withContext ApkExtractionOutcome.Incomplete("APK exceeds the configured input bound.")
        }

        try {
            ZipInputStream(BufferedInputStream(FileInputStream(apk), BUFFER_SIZE)).use { zip ->
                var manifest: ApkComponent? = null
                val dexComponents = mutableListOf<ApkComponent>()
                val seenTargets = HashSet<String>()
                var totalExtracted = 0L
                var inspectedEntries = 0

                while (true) {
                    currentCoroutineContext().ensureActive()
                    val entry = zip.nextEntry ?: break
                    inspectedEntries++
                    if (inspectedEntries > MAX_ARCHIVE_ENTRIES) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK entry-count limit exceeded.")
                    }
                    if (entry.isDirectory) {
                        zip.closeEntry()
                        continue
                    }

                    val isManifest = entry.name == MANIFEST_ENTRY
                    val isDex = DEX_ENTRY.matches(entry.name)
                    if (!isManifest && !isDex) {
                        // Advance without allocating or scanning image, asset, resource, or native-library data.
                        zip.closeEntry()
                        continue
                    }

                    if (!seenTargets.add(entry.name)) {
                        return@withContext ApkExtractionOutcome.Incomplete("Duplicate APK scan entry.")
                    }

                    val limit = if (isManifest) MAX_MANIFEST_BYTES else MAX_SINGLE_DEX_BYTES
                    if (entry.size > limit) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK scan entry exceeds its declared size bound.")
                    }
                    if (entry.compressedSize == 0L && entry.size > 0L) {
                        return@withContext ApkExtractionOutcome.Incomplete("Invalid compressed APK entry.")
                    }
                    if (entry.compressedSize > 0L && entry.size >= 0L &&
                        entry.size.toDouble() / entry.compressedSize.toDouble() > MAX_COMPRESSION_RATIO
                    ) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK compression-ratio limit exceeded.")
                    }

                    val bytes = readBounded(zip, limit.toInt())
                    zip.closeEntry()
                    if (entry.size >= 0L && entry.size != bytes.size.toLong()) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK entry size did not match its streamed bytes.")
                    }
                    if (entry.compressedSize == 0L && bytes.isNotEmpty()) {
                        return@withContext ApkExtractionOutcome.Incomplete("Invalid compressed APK entry.")
                    }
                    if (entry.compressedSize > 0L &&
                        bytes.size.toDouble() / entry.compressedSize.toDouble() > MAX_COMPRESSION_RATIO
                    ) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK compression-ratio limit exceeded.")
                    }
                    if (totalExtracted + bytes.size > MAX_TOTAL_EXTRACTED_BYTES) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK aggregate extraction limit exceeded.")
                    }
                    totalExtracted += bytes.size

                    val component = ApkComponent(entry.name, bytes)
                    if (isManifest) manifest = component else dexComponents += component
                }

                val manifestComponent = manifest
                    ?: return@withContext ApkExtractionOutcome.Incomplete("AndroidManifest.xml is missing.")
                if (dexComponents.isEmpty()) {
                    return@withContext ApkExtractionOutcome.Incomplete("No classes*.dex entry was found.")
                }

                ApkExtractionOutcome.Complete(
                    listOf(manifestComponent) + dexComponents.sortedBy { it.entryName }
                )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            ApkExtractionOutcome.Incomplete(
                "APK streaming failed: ${error.javaClass.simpleName}."
            )
        }
    }

    private suspend fun readBounded(input: ZipInputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(limit, BUFFER_SIZE))
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0
        while (true) {
            currentCoroutineContext().ensureActive()
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            total += count
            if (total > limit) throw IOException("APK entry exceeded its streaming bound.")
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private companion object {
        const val MANIFEST_ENTRY = "AndroidManifest.xml"
        const val BUFFER_SIZE = 8192
        const val MAX_APK_BYTES = 512L * 1024L * 1024L
        const val MAX_ARCHIVE_ENTRIES = 10_000
        const val MAX_MANIFEST_BYTES = 2L * 1024L * 1024L
        const val MAX_SINGLE_DEX_BYTES = 16L * 1024L * 1024L
        const val MAX_TOTAL_EXTRACTED_BYTES = 32L * 1024L * 1024L
        const val MAX_COMPRESSION_RATIO = 200.0
        val DEX_ENTRY = Regex("""classes(?:[0-9]+)?\.dex""")
    }
}
