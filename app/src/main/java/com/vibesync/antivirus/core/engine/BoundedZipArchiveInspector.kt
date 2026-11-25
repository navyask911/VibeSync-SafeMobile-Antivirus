package com.vibesync.antivirus.core.engine

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.ZipInputStream

internal data class ArchiveEntryPayload(
    val entryName: String,
    val bytes: ByteArray
)

internal data class ArchiveInspectionSummary(
    val inspectedEntries: Int,
    val complete: Boolean,
    val reason: String? = null
)

/** Bounded ZIP/JAR traversal. All payloads are streamed one at a time and paths are never extracted. */
internal object BoundedZipArchiveInspector {
    private const val MAX_ENTRIES = 10_000
    private const val MAX_ENTRY_BYTES = 128L * 1024L * 1024L
    private const val MAX_TOTAL_EXPANDED_BYTES = 384L * 1024L * 1024L
    private const val MAX_IGNORED_ENTRY_BYTES = 512L * 1024L * 1024L
    private const val MAX_IGNORED_TOTAL_BYTES = 768L * 1024L * 1024L
    private const val MAX_COMPRESSION_RATIO = 200.0
    private const val BUFFER_SIZE = 8 * 1024

    private data class Budget(
        var entries: Int = 0,
        var inspected: Int = 0,
        var expandedBytes: Long = 0L,
        var ignoredBytes: Long = 0L,
        var reason: String? = null
    )

    suspend fun inspect(
        archive: File,
        includeAllLeafEntries: Boolean,
        maxDepth: Int = 2,
        onEntry: suspend (ArchiveEntryPayload) -> Unit
    ): ArchiveInspectionSummary {
        if (!archive.isFile || !archive.canRead()) {
            return ArchiveInspectionSummary(0, false, "Archive is not a readable file.")
        }
        val budget = Budget()
        val complete = try {
            visit(
                FileInputStream(archive),
                archive.name,
                depth = 0,
                maxDepth = maxDepth.coerceIn(0, 3),
                includeAllLeafEntries = includeAllLeafEntries,
                budget = budget,
                onEntry = onEntry
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            budget.reason = budget.reason ?: "Archive inspection failed: ${error.javaClass.simpleName}."
            false
        }
        return ArchiveInspectionSummary(
            inspectedEntries = budget.inspected,
            complete = complete && budget.reason == null,
            reason = budget.reason
        )
    }

    private suspend fun visit(
        source: InputStream,
        prefix: String,
        depth: Int,
        maxDepth: Int,
        includeAllLeafEntries: Boolean,
        budget: Budget,
        onEntry: suspend (ArchiveEntryPayload) -> Unit
    ): Boolean {
        var localFiles = 0
        val zip = ZipInputStream(BufferedInputStream(source, BUFFER_SIZE))
        try {
            while (true) {
                currentCoroutineContext().ensureActive()
                val entry = zip.nextEntry ?: break
                budget.entries++
                if (budget.entries > MAX_ENTRIES) {
                    budget.reason = "Archive entry-count limit exceeded."
                    return false
                }
                if (entry.isDirectory) {
                    zip.closeEntry()
                    continue
                }
                localFiles++

                val name = safeName(entry.name)
                val isApk = name.endsWith(".apk", ignoreCase = true)
                val isZipName = name.endsWith(".zip", ignoreCase = true) ||
                    name.endsWith(".jar", ignoreCase = true)
                // For APKs, drain unrelated resources without buffering or scanning them.
                if (!includeAllLeafEntries && !isApk && !isZipName) {
                    if (!discardEntry(zip, budget)) return false
                    zip.closeEntry()
                    continue
                }
                if (entry.size > MAX_ENTRY_BYTES) {
                    budget.reason = "Archive entry exceeds the 128 MiB inspection limit: $name."
                    return false
                }
                if (entry.compressedSize > 0L && entry.size > 0L &&
                    entry.size.toDouble() / entry.compressedSize.toDouble() > MAX_COMPRESSION_RATIO
                ) {
                    budget.reason = "Archive compression-ratio limit exceeded: $name."
                    return false
                }

                val bytes = readBounded(zip, budget)
                zip.closeEntry()
                val entryPath = if (prefix.isBlank()) name else "$prefix!/$name"
                val isZipPayload = hasZipHeader(bytes)

                if (isZipPayload && !isApk) {
                    if (depth >= maxDepth) {
                        budget.reason = "Nested archive depth limit exceeded at $entryPath."
                        return false
                    }
                    if (!visit(
                            ByteArrayInputStream(bytes),
                            entryPath,
                            depth + 1,
                            maxDepth,
                            includeAllLeafEntries = true,
                            budget = budget,
                            onEntry = onEntry
                        )
                    ) return false
                } else if (includeAllLeafEntries || isApk || isZipName) {
                    budget.inspected++
                    onEntry(ArchiveEntryPayload(entryPath, bytes))
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            budget.reason = budget.reason ?: "Archive entry could not be read: ${error.javaClass.simpleName}."
            return false
        } finally {
            runCatching { zip.close() }
        }

        if (localFiles == 0) {
            budget.reason = budget.reason ?: "Archive contains no readable file entries."
            return false
        }
        return true
    }

    /** Drain unrelated APK resources without retaining their bytes, but keep traversal bounded. */
    private suspend fun discardEntry(input: ZipInputStream, budget: Budget): Boolean {
        val buffer = ByteArray(BUFFER_SIZE)
        var entryBytes = 0L
        while (true) {
            currentCoroutineContext().ensureActive()
            val count = input.read(buffer)
            if (count < 0) return true
            if (count == 0) continue
            entryBytes += count
            budget.ignoredBytes += count
            if (entryBytes > MAX_IGNORED_ENTRY_BYTES ||
                budget.ignoredBytes > MAX_IGNORED_TOTAL_BYTES
            ) {
                budget.reason = "Unselected APK resources exceeded the bounded drain limit."
                return false
            }
        }
    }

    private suspend fun readBounded(input: ZipInputStream, budget: Budget): ByteArray {
        val output = ByteArrayOutputStream(BUFFER_SIZE)
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0L
        while (true) {
            currentCoroutineContext().ensureActive()
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            total += count
            budget.expandedBytes += count
            if (total > MAX_ENTRY_BYTES) throw IOException("Archive entry exceeds its inspection limit.")
            if (budget.expandedBytes > MAX_TOTAL_EXPANDED_BYTES) {
                throw IOException("Archive aggregate expansion exceeds its inspection limit.")
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun hasZipHeader(bytes: ByteArray): Boolean =
        bytes.size >= 4 &&
            bytes[0] == 0x50.toByte() &&
            bytes[1] == 0x4b.toByte() &&
            bytes[2] in setOf(0x03.toByte(), 0x05.toByte(), 0x07.toByte()) &&
            bytes[3] in setOf(0x04.toByte(), 0x06.toByte(), 0x08.toByte())

    private fun safeName(value: String): String =
        value.split('/').filter { it.isNotBlank() && it != "." && it != ".." }
            .joinToString("/").take(240).ifBlank { "unnamed-entry" }
}
