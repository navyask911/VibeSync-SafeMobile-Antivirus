package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import androidx.documentfile.provider.DocumentFile
import com.vibesync.antivirus.SafeMobileApp
import org.json.JSONArray

private val Context.customFolderDataStore by preferencesDataStore(name = "safemobile_custom_folder_uris")

/** Explicit, additive SAF grants. Revoking one folder never discards the other grants. */
object StorageAccessPreferences {
    private const val LEGACY_TREE = "downloads_sentinel_tree_uri"
    private const val TREES = "sentinel_tree_uris_v2"
    const val DOWNLOADS = "downloads"
    const val WHATSAPP = "whatsapp"
    const val CUSTOM = "custom"
    const val MAX_CUSTOM_FOLDERS = 10
    private val CUSTOM_TREE_URIS = stringSetPreferencesKey("custom_tree_uris")
    private fun prefs(context: Context) = context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)

    fun selectedTreeUris(context: Context): List<Uri> {
        val preferences = prefs(context)
        val saved = preferences.getString(TREES, null)
        val values = if (saved == null) listOfNotNull(preferences.getString(LEGACY_TREE, null)) else
            runCatching { val array = JSONArray(saved); (0 until array.length()).map { array.getString(it) } }.getOrDefault(emptyList())
        return values.distinct().mapNotNull { value ->
            runCatching { Uri.parse(value).takeIf { it.scheme == "content" && DocumentsContract.isTreeUri(it) } }.getOrNull()
        }
    }

    // Compatibility for old callers; new monitoring always traverses selectedTreeUris.
    fun selectedTreeUri(context: Context): Uri? = selectedTreeUris(context).firstOrNull()

    fun accessibleTreeUris(context: Context): List<Uri> {
        val grants = runCatching { context.contentResolver.persistedUriPermissions.filter { it.isReadPermission }.map { it.uri }.toSet() }
            .getOrDefault(emptySet())
        return selectedTreeUris(context).filter { it in grants }
    }
    fun hasAccess(context: Context): Boolean = accessibleTreeUris(context).isNotEmpty()
    fun roleUri(context: Context, role: String): Uri? = prefs(context).getString("sentinel_role_$role", null)?.let(Uri::parse)
    fun hasRole(context: Context, role: String): Boolean = accessibleTreeUris(context).any { matchesRole(it, role) }
    fun matchesRole(uri: Uri, role: String): Boolean {
        val id = runCatching { DocumentsContract.getTreeDocumentId(uri).lowercase() }.getOrDefault("")
        val parts = id.split(':', '/')
        return when (role) {
            DOWNLOADS -> parts.any { it == "download" || it == "downloads" }
            WHATSAPP -> parts.any { it == "whatsapp" || it == "whatsapp business" || it == "whatsapp documents" }
            else -> false
        }
    }
    fun displayName(uri: Uri): String = runCatching { DocumentsContract.getTreeDocumentId(uri).substringAfter(':').ifBlank { "Storage" } }.getOrDefault("Selected folder")
    fun isStorageRoot(uri: Uri): Boolean = runCatching {
        uri.authority == "com.android.externalstorage.documents" && DocumentsContract.getTreeDocumentId(uri).endsWith(':')
    }.getOrDefault(false)

    fun pickerIntent(role: String): Intent = Intent(Intent.ACTION_OPEN_DOCUMENT_TREE).apply {
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
            Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
        if (role != CUSTOM) {
            val path = if (role == WHATSAPP) "primary:Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents" else "primary:Download"
            putExtra(DocumentsContract.EXTRA_INITIAL_URI, DocumentsContract.buildDocumentUri("com.android.externalstorage.documents", path))
        }
    }

    /** Called on IO after a user selection, with exactly the permissions returned by the picker. */
    @Synchronized
    fun persistSelectedFolder(context: Context, uri: Uri, role: String = DOWNLOADS,
        grantFlags: Int = Intent.FLAG_GRANT_READ_URI_PERMISSION): Boolean {
        if (isStorageRoot(uri) || !DocumentsContract.isTreeUri(uri)) return false
        val root = runCatching { DocumentFile.fromTreeUri(context, uri) }.getOrNull() ?: return false
        if (!root.isDirectory || !root.canRead()) return false
        val resolver = context.contentResolver
        try { resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        catch (_: SecurityException) { return false }
        if (grantFlags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION != 0) {
            runCatching { resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
        }
        val uris = (selectedTreeUris(context).map(Uri::toString) + uri.toString()).distinct()
        return prefs(context).edit().putString(TREES, JSONArray(uris).toString())
            .putString("sentinel_role_$role", uri.toString()).remove(LEGACY_TREE).commit()
    }

    /** DataStore is the source of truth for the user-managed custom-folder set. */
    fun observeCustomTreeUris(context: Context): Flow<List<Uri>> =
        context.customFolderDataStore.data.map { preferences ->
            preferences[CUSTOM_TREE_URIS].orEmpty().mapNotNull { value ->
                runCatching {
                    Uri.parse(value).takeIf { it.scheme == "content" && DocumentsContract.isTreeUri(it) }
                }.getOrNull()
            }.sortedBy(Uri::toString)
        }

    suspend fun customTreeUris(context: Context): List<Uri> {
        val granted = runCatching {
            context.contentResolver.persistedUriPermissions
                .filter { it.isReadPermission }
                .map { it.uri }
                .toSet()
        }.getOrDefault(emptySet())
        return observeCustomTreeUris(context).first().filter { it in granted }
    }

    /** Persists only an SAF tree URI; read access is granted persistently before DataStore is updated. */
    suspend fun persistCustomFolder(context: Context, uri: Uri, grantFlags: Int): Boolean {
        if (!DocumentsContract.isTreeUri(uri) || isStorageRoot(uri)) return false
        val current = customTreeUris(context)
        if (uri !in current && current.size >= MAX_CUSTOM_FOLDERS) return false
        if (!persistSelectedFolder(context, uri, CUSTOM, grantFlags)) return false
        context.customFolderDataStore.edit { preferences ->
            preferences[CUSTOM_TREE_URIS] = (current + uri).map(Uri::toString).toSet()
        }
        return true
    }

    /** Removes custom DataStore membership and the shared watcher index/grant together. */
    suspend fun removeSelectedFolder(context: Context, uri: Uri) {
        val current = customTreeUris(context)
        if (uri in current) {
            context.customFolderDataStore.edit { preferences ->
                preferences[CUSTOM_TREE_URIS] = current.filterNot { it == uri }.map(Uri::toString).toSet()
            }
        }
        removeFolder(context, uri)
    }

    @Synchronized
    fun removeFolder(context: Context, uri: Uri) {
        val editor = prefs(context).edit().putString(TREES,
            JSONArray(selectedTreeUris(context).filterNot { it == uri }.map(Uri::toString)).toString()).remove(LEGACY_TREE)
        for (role in listOf(DOWNLOADS, WHATSAPP)) if (roleUri(context, role) == uri) editor.remove("sentinel_role_$role")
        if (!editor.commit()) return
        runCatching { context.contentResolver.releasePersistableUriPermission(uri,
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION) }
    }
}
