package com.vibesync.antivirus.core.engine.yara

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.zip.CRC32
import java.util.zip.ZipFile

data class ApkComponent(val entryName: String, val bytes: ByteArray)
sealed class ApkExtractionOutcome {
    data class Complete(val entryNames: List<String>) : ApkExtractionOutcome()
    data class Incomplete(val reason: String) : ApkExtractionOutcome()
}

/**
 * Uses the APK central directory to read only the root binary manifest and DEX
 * components. Unrelated resources are not inflated just to advance a ZIP cursor,
 * avoiding false partial coverage and unbounded work on irrelevant payloads.
 */
class ApkContentExtractor {
    suspend fun forEachComponent(
        apk: File,
        allowManifestOnly: Boolean = false,
        onComponent: suspend (ApkComponent) -> Boolean
    ): ApkExtractionOutcome = withContext(Dispatchers.IO) {
        if (!apk.isFile || !apk.canRead()) {
            return@withContext ApkExtractionOutcome.Incomplete("APK is not a readable file.")
        }
        if (apk.length() !in 1..MAX_APK_BYTES) {
            return@withContext ApkExtractionOutcome.Incomplete("APK exceeds the configured input bound.")
        }
        try {
            ZipFile(apk).use { zip ->
                var manifestSeen = false
                var dexCount = 0
                val seenTargets = HashSet<String>()
                val targetNames = mutableListOf<String>()
                var totalExtracted = 0L
                var inspectedEntries = 0
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    currentCoroutineContext().ensureActive()
                    val entry = entries.nextElement()
                    inspectedEntries++
                    if (inspectedEntries > MAX_ARCHIVE_ENTRIES) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK entry-count limit exceeded.")
                    }
                    if (entry.isDirectory) continue
                    val isManifest = entry.name == MANIFEST_ENTRY
                    val isDex = DEX_ENTRY.matches(entry.name)
                    if (!isManifest && !isDex) continue
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
                    val bytes = zip.getInputStream(entry).use { readBounded(it, limit.toInt()) }
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
                    if (entry.crc >= 0L && CRC32().apply { update(bytes) }.value != entry.crc) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK target entry checksum mismatch.")
                    }
                    if (totalExtracted + bytes.size > MAX_TOTAL_EXTRACTED_BYTES) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK aggregate extraction limit exceeded.")
                    }
                    totalExtracted += bytes.size
                    if (!onComponent(ApkComponent(entry.name, bytes))) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK component processing stopped.")
                    }
                    targetNames += entry.name
                    if (isManifest) manifestSeen = true else dexCount++
                }
                if (!manifestSeen) {
                    return@withContext ApkExtractionOutcome.Incomplete("AndroidManifest.xml is missing.")
                }
                if (dexCount == 0 && !allowManifestOnly) {
                    return@withContext ApkExtractionOutcome.Incomplete("No classes*.dex entry was found.")
                }
                ApkExtractionOutcome.Complete(targetNames)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            ApkExtractionOutcome.Incomplete("APK central-directory scan failed: ${error.javaClass.simpleName}.")
        }
    }

    private suspend fun readBounded(input: InputStream, limit: Int): ByteArray {
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
        const val MAX_ARCHIVE_ENTRIES = 20_000
        const val MAX_MANIFEST_BYTES = 2L * 1024L * 1024L
        const val MAX_SINGLE_DEX_BYTES = 128L * 1024L * 1024L
        const val MAX_TOTAL_EXTRACTED_BYTES = 384L * 1024L * 1024L
        const val MAX_COMPRESSION_RATIO = 200.0
        val DEX_ENTRY = Regex("""classes(?:[0-9]+)?\.dex""")
    }
}
