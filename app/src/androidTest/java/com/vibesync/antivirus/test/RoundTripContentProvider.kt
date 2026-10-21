package com.vibesync.antivirus.test

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import java.io.File

/** Test-only exported provider gives the target app a content:// destination for quarantine restore. */
class RoundTripContentProvider : ContentProvider() {
    override fun onCreate() = true
    override fun getType(uri: Uri): String = "application/octet-stream"
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val columns = projection ?: arrayOf("_display_name")
        return MatrixCursor(columns).apply {
            val row = newRow()
            columns.forEach { column -> if (column == "_display_name") row.add(uri.lastPathSegment ?: "restored-file") else row.add(null) }
        }
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = if (target(uri).delete()) 1 else 0
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        val file = target(uri)
        file.parentFile?.mkdirs()
        val flags = if (mode.contains("w")) {
            ParcelFileDescriptor.MODE_CREATE or ParcelFileDescriptor.MODE_TRUNCATE or ParcelFileDescriptor.MODE_WRITE_ONLY
        } else ParcelFileDescriptor.MODE_READ_ONLY
        return ParcelFileDescriptor.open(file, flags)
    }
    private fun target(uri: Uri): File {
        val name = (uri.lastPathSegment ?: "restored-file").replace(Regex("[^A-Za-z0-9_-]"), "_")
        return File(requireNotNull(context).cacheDir, "safe-mobile-roundtrip-" + name)
    }
}
