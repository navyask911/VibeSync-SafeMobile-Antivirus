package com.vibesync.antivirus.core.observer

import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.documentfile.provider.DocumentFile
import java.util.ArrayDeque

/** Iterative traversal has no depth limit and stays inside the explicitly granted trees. Call on IO. */
object SafTreeWalker {
    fun files(context: Context, roots: List<Uri>): Sequence<DocumentFile> = sequence {
        val pending = ArrayDeque<DocumentFile>()
        val visited = HashSet<String>()
        for (uri in roots) runCatching { DocumentFile.fromTreeUri(context, uri) }.getOrNull()?.let(pending::addLast)
        while (pending.isNotEmpty()) {
            val directory = pending.removeFirst()
            if (!visited.add(directory.uri.toString())) continue
            val children = runCatching { if (directory.canRead()) directory.listFiles() else emptyArray() }
                .getOrElse { Log.w("SafeMobileSentinel", "A granted folder could not be listed", it); emptyArray() }
            for (child in children) {
                try {
                    if (child.isDirectory) pending.addLast(child)
                    else if (child.isFile && visited.add(child.uri.toString()) && child.canRead()) yield(child)
                } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
                catch (failure: Exception) { Log.w("SafeMobileSentinel", "One granted entry was unavailable; continuing", failure) }
            }
        }
    }
}
