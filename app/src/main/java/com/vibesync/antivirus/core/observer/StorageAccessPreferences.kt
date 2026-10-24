package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import com.vibesync.antivirus.SafeMobileApp

/** Stores the user's explicit SAF folder grant. No broad shared-storage permission is required. */
object StorageAccessPreferences {
    private const val TREE_URI_KEY = "downloads_sentinel_tree_uri"

    fun selectedTreeUri(context: Context): Uri? =
        context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .getString(TREE_URI_KEY, null)
            ?.let { value -> runCatching { Uri.parse(value) }.getOrNull() }

    fun hasAccess(context: Context): Boolean {
        val uri = selectedTreeUri(context) ?: return false
        val persisted = context.contentResolver.persistedUriPermissions.any {
            it.uri == uri && it.isReadPermission
        }
        if (!persisted) return false
        return runCatching { DocumentFile.fromTreeUri(context, uri)?.canRead() == true }.getOrDefault(false)
    }

    /** Persists only the folder deliberately selected in the Android document picker. */
    fun persistSelectedFolder(context: Context, uri: Uri): Boolean {
        val resolver = context.contentResolver
        val previous = selectedTreeUri(context)
        val grants = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        try {
            resolver.takePersistableUriPermission(uri, grants)
        } catch (_: SecurityException) {
            // Some providers offer read-only trees. Retain the minimum permission needed to scan.
            resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val saved = context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .edit().putString(TREE_URI_KEY, uri.toString()).commit()
        if (!saved) return false
        if (previous != null && previous != uri) {
            runCatching {
                resolver.releasePersistableUriPermission(
                    previous,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
        }
        return hasAccess(context)
    }
}
