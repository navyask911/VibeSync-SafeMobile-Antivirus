package com.vibesync.antivirus.core.observer

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import java.util.ArrayDeque

/** Bounded SAF traversal remains inside the user-granted trees. Run on IO. */
object SafTreeWalker {
    private const val MAX_DIRECTORY_VISITS = 10_000

    fun files(
        context: Context,
        roots: List<Uri>,
        maxDepth: Int = 10,
        maxFiles: Int = 1_000,
        onFileError: (Uri, Exception) -> Unit = { _, _ -> }
    ): Sequence<DocumentFile> = sequence {
        data class PendingDirectory(val document: DocumentFile, val depth: Int)
        val pending = ArrayDeque<PendingDirectory>()
        val visitedDirectories = HashSet<String>()
        val visitedFiles = HashSet<String>()
        var inspectedFiles = 0

        for (uri in roots) {
            try {
                DocumentFile.fromTreeUri(context, uri)?.let { pending.addLast(PendingDirectory(it, 0)) }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Log.e("ScanDebug", "Unable to open selected SAF root: " + uri, error)
            }
        }

        while (pending.isNotEmpty() && inspectedFiles < maxFiles && visitedDirectories.size < MAX_DIRECTORY_VISITS) {
            val (directory, depth) = pending.removeFirst()
            val directoryKey = directory.uri.toString()
            if (depth > maxDepth || !visitedDirectories.add(directoryKey)) continue
            val children = try {
                if (directory.canRead()) directory.listFiles() else emptyArray()
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Log.e("ScanDebug", "Unable to enumerate selected SAF directory: " + directoryKey, error)
                emptyArray()
            }

            for (child in children) {
                if (inspectedFiles >= maxFiles) break
                try {
                    val childUri = child.uri
                    when {
                        child.isDirectory -> {
                            if (depth + 1 <= maxDepth) pending.addLast(PendingDirectory(child, depth + 1))
                        }
                        child.isFile && visitedFiles.add(childUri.toString()) -> {
                            inspectedFiles += 1
                            // Keep enumeration independent of optional provider name/size metadata.
                            Log.v("ScanDebug", "Enumerated SAF document: " + childUri)
                            if (child.canRead()) yield(child)
                            else onFileError(childUri, SecurityException("The selected SAF document is not readable."))
                        }
                    }
                } catch (cancelled: kotlinx.coroutines.CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    val failedUri = runCatching { child.uri }.getOrNull()
                    if (failedUri != null) onFileError(failedUri, error)
                    else Log.e("ScanDebug", "Skipping an SAF entry whose URI could not be read.", error)
                }
            }
        }
    }
}
