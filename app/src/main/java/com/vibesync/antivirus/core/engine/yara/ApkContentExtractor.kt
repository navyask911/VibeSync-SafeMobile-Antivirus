package com.vibesync.antivirus.core.engine.yara

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.zip.ZipFile

data class ApkComponent(
    val entryName: String,
    val bytes: ByteArray
)

sealed class ApkExtractionOutcome {
    data class Complete(val components: List<ApkComponent>) : ApkExtractionOutcome()
    data class Incomplete(val reason: String) : ApkExtractionOutcome()
}

/**
 * Extracts only the root AndroidManifest.xml and root classes*.dex ZIP entries.
 * No extracted content is written to shared or temporary storage.
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
            ZipFile(apk).use { zip ->
                var manifest: ApkComponent? = null
                val dexComponents = mutableListOf<ApkComponent>()
                val seenTargets = HashSet<String>()
                var totalExtracted = 0L
                var inspectedEntries = 0

                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    inspectedEntries++
                    if (inspectedEntries > MAX_ARCHIVE_ENTRIES) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK entry-count limit exceeded.")
                    }
                    if (entry.isDirectory) continue

                    val isManifest = entry.name == MANIFEST_ENTRY
                    val isDex = DEX_ENTRY.matches(entry.name)
                    if (!isManifest && !isDex) continue

                    // Only exact root entry names are accepted. No path is ever
                    // written to disk, so traversal entries cannot escape a directory.
                    if (!seenTargets.add(entry.name)) {
                        return@withContext ApkExtractionOutcome.Incomplete("Duplicate APK scan entry.")
                    }

                    val limit = if (isManifest) MAX_MANIFEST_BYTES else MAX_SINGLE_DEX_BYTES
                    if (entry.size < 0L || entry.size > limit) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK scan entry exceeds its declared size bound.")
                    }
                    if (entry.compressedSize == 0L && entry.size > 0L) {
                        return@withContext ApkExtractionOutcome.Incomplete("Invalid compressed APK entry.")
                    }
                    if (entry.compressedSize > 0L &&
                        entry.size.toDouble() / entry.compressedSize.toDouble() > MAX_COMPRESSION_RATIO
                    ) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK compression-ratio limit exceeded.")
                    }
                    if (totalExtracted + entry.size > MAX_TOTAL_EXTRACTED_BYTES) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK aggregate extraction limit exceeded.")
                    }

                    val bytes = zip.getInputStream(entry).use { input ->
                        readBounded(input, limit.toInt())
                    }
                    if (entry.size != bytes.size.toLong()) {
                        return@withContext ApkExtractionOutcome.Incomplete("APK entry size did not match its extracted bytes.")
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
                "APK extraction failed: ${error.javaClass.simpleName}."
            )
        }
    }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(limit, BUFFER_SIZE))
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            total += count
            if (total > limit) throw IOException("APK entry exceeded its extraction bound.")
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
        val DEX_ENTRY = Regex("""classes(?:[2-9][0-9]*)?\.dex""")
    }
}
