package com.vibesync.antivirus.core.engine

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipInputStream

internal data class ArchiveEntryPayload(val entryName: String, val bytes: ByteArray)
internal data class ArchiveInspectionSummary(val inspectedEntries: Int, val complete: Boolean, val reason: String? = null)

/**
 * Bounded ZIP/JAR traversal. The root archive uses its central directory so APK
 * resources outside the scan scope are never decompressed just to reach scan targets.
 * Nested archives are walked from bounded byte arrays; paths are never extracted.
 */
internal object BoundedZipArchiveInspector {
    private const val MAX_ENTRIES = 20_000
    private const val MAX_ENTRY_BYTES = 128L * 1024L * 1024L
    private const val MAX_TOTAL_EXPANDED_BYTES = 384L * 1024L * 1024L
    private const val MAX_COMPRESSION_RATIO = 200.0
    private const val BUFFER_SIZE = 8 * 1024

    private data class Budget(
        var entries: Int = 0,
        var inspected: Int = 0,
        var expandedBytes: Long = 0L,
        var reason: String? = null,
        var hardLimitExceeded: Boolean = false
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
            ZipFile(archive).use { zip ->
                visitFile(zip, archive.name, 0, maxDepth.coerceIn(0, 3), includeAllLeafEntries, budget, onEntry)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            budget.reason = budget.reason ?: "Archive inspection failed: ${error.javaClass.simpleName}."
            false
        }
        return ArchiveInspectionSummary(budget.inspected, complete && budget.reason == null, budget.reason)
    }

    private suspend fun visitFile(
        zip: ZipFile,
        prefix: String,
        depth: Int,
        maxDepth: Int,
        includeAllLeafEntries: Boolean,
        budget: Budget,
        onEntry: suspend (ArchiveEntryPayload) -> Unit
    ): Boolean {
        var localFiles = 0
        val entries = zip.entries()
        while (entries.hasMoreElements()) {
            currentCoroutineContext().ensureActive()
            val entry = entries.nextElement()
            if (!incrementEntryBudget(budget)) return false
            if (entry.isDirectory) continue
            localFiles++
            val name = safeName(entry.name)
            val isApk = name.endsWith(".apk", true)
            val isZipName = name.endsWith(".zip", true) || name.endsWith(".jar", true)
            // In APK mode, skip unrelated resources by central-directory metadata;
            // they are outside embedded-archive analysis and are never inflated.
            if (!includeAllLeafEntries && !isApk && !isZipName) continue
            if (!entryWithinBounds(entry, name, budget)) return false
            val bytes = try {
                zip.getInputStream(entry).use { readBounded(it, name, budget) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                budget.reason = budget.reason
                    ?: "Archive entry could not be read: ${error.javaClass.simpleName}: $name."
                if (budget.hardLimitExceeded) return false
                continue
            }
            if (!hasValidCrc(entry, bytes)) {
                budget.reason = budget.reason ?: "Archive entry checksum mismatch: $name."
                // The central directory lets us continue to independent sibling entries.
                continue
            }
            val entryPath = if (prefix.isBlank()) name else "$prefix!/$name"
            if (!inspectPayload(bytes, entryPath, isApk, depth, maxDepth, budget, onEntry)) return false
        }
        if (localFiles == 0) {
            budget.reason = budget.reason ?: "Archive contains no readable file entries."
            return false
        }
        return !budget.hardLimitExceeded
    }

    private suspend fun visitNested(
        source: InputStream,
        prefix: String,
        depth: Int,
        maxDepth: Int,
        budget: Budget,
        onEntry: suspend (ArchiveEntryPayload) -> Unit
    ): Boolean {
        var localFiles = 0
        val zip = ZipInputStream(BufferedInputStream(source, BUFFER_SIZE))
        try {
            while (true) {
                currentCoroutineContext().ensureActive()
                val entry = zip.nextEntry ?: break
                if (!incrementEntryBudget(budget)) return false
                if (entry.isDirectory) {
                    zip.closeEntry()
                    continue
                }
                localFiles++
                val name = safeName(entry.name)
                val isApk = name.endsWith(".apk", true)
                if (!entryWithinBounds(entry, name, budget)) return false
                val bytes = readBounded(zip, name, budget)
                zip.closeEntry()
                if (!hasValidCrc(entry, bytes)) {
                    budget.reason = budget.reason ?: "Nested archive entry checksum mismatch: $name."
                    return false
                }
                if (!inspectPayload(bytes, "$prefix!/$name", isApk, depth, maxDepth, budget, onEntry)) return false
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            budget.reason = budget.reason ?: "Nested archive entry could not be read: ${error.javaClass.simpleName}."
            return false
        } finally {
            runCatching { zip.close() }
        }
        if (localFiles == 0) {
            budget.reason = budget.reason ?: "Nested archive contains no readable file entries."
            return false
        }
        return !budget.hardLimitExceeded
    }

    private suspend fun inspectPayload(
        bytes: ByteArray,
        entryPath: String,
        isApk: Boolean,
        depth: Int,
        maxDepth: Int,
        budget: Budget,
        onEntry: suspend (ArchiveEntryPayload) -> Unit
    ): Boolean {
        if (hasZipHeader(bytes) && !isApk) {
            if (depth >= maxDepth) {
                budget.reason = budget.reason ?: "Nested archive depth limit exceeded at $entryPath."
                return true
            }
            val nestedComplete = visitNested(ByteArrayInputStream(bytes), entryPath, depth + 1, maxDepth, budget, onEntry)
            // A malformed nested tree is partial, but readable sibling entries in
            // the containing archive are still inspected. Hard limits remain terminal.
            return nestedComplete || !budget.hardLimitExceeded
        }
        budget.inspected++
        onEntry(ArchiveEntryPayload(entryPath, bytes))
        return true
    }

    private fun incrementEntryBudget(budget: Budget): Boolean {
        budget.entries++
        if (budget.entries <= MAX_ENTRIES) return true
        budget.hardLimitExceeded = true
        budget.reason = budget.reason ?: "Archive entry-count limit exceeded."
        return false
    }

    private fun entryWithinBounds(entry: ZipEntry, name: String, budget: Budget): Boolean {
        if (entry.size > MAX_ENTRY_BYTES) {
            budget.hardLimitExceeded = true
            budget.reason = budget.reason ?: "Archive entry exceeds the 128 MiB inspection limit: $name."
            return false
        }
        if (entry.compressedSize == 0L && entry.size > 0L) {
            budget.hardLimitExceeded = true
            budget.reason = budget.reason ?: "Invalid compressed archive entry: $name."
            return false
        }
        if (entry.compressedSize > 0L && entry.size > 0L &&
            entry.size.toDouble() / entry.compressedSize.toDouble() > MAX_COMPRESSION_RATIO
        ) {
            budget.hardLimitExceeded = true
            budget.reason = budget.reason ?: "Archive compression-ratio limit exceeded: $name."
            return false
        }
        return true
    }

    private suspend fun readBounded(input: InputStream, name: String, budget: Budget): ByteArray {
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
            if (total > MAX_ENTRY_BYTES) {
                budget.hardLimitExceeded = true
                budget.reason = budget.reason ?: "Archive entry exceeds its inspection limit: $name."
                throw IOException("Archive entry exceeds its inspection limit.")
            }
            if (budget.expandedBytes > MAX_TOTAL_EXPANDED_BYTES) {
                budget.hardLimitExceeded = true
                budget.reason = budget.reason ?: "Archive aggregate expansion exceeds its inspection limit."
                throw IOException("Archive aggregate expansion exceeds its inspection limit.")
            }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun hasValidCrc(entry: ZipEntry, bytes: ByteArray): Boolean {
        if (entry.crc < 0L) return true
        return CRC32().apply { update(bytes) }.value == entry.crc
    }

    private fun hasZipHeader(bytes: ByteArray): Boolean =
        bytes.size >= 4 && bytes[0] == 0x50.toByte() && bytes[1] == 0x4b.toByte() &&
            bytes[2] in setOf(0x03.toByte(), 0x05.toByte(), 0x07.toByte()) &&
            bytes[3] in setOf(0x04.toByte(), 0x06.toByte(), 0x08.toByte())

    private fun safeName(value: String): String =
        value.split('/').filter { it.isNotBlank() && it != "." && it != ".." }
            .joinToString("/").take(240).ifBlank { "unnamed-entry" }
}
