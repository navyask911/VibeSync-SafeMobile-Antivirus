package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import com.vibesync.antivirus.SafeMobileApp
import org.junit.Assert.*
import org.junit.Test

class StorageAccessPreferencesTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    @Test fun pickerUsesTreeAccessAndRejectsOnlyAbsoluteStorageRootInOurCode() {
        val root = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3A")
        val downloads = Uri.parse("content://com.android.externalstorage.documents/tree/primary%3ADownload")
        assertTrue(StorageAccessPreferences.isStorageRoot(root))
        assertFalse(StorageAccessPreferences.isStorageRoot(downloads))
        assertFalse(StorageAccessPreferences.persistSelectedFolder(context, root))
        assertEquals(Intent.ACTION_OPEN_DOCUMENT_TREE, StorageAccessPreferences.pickerIntent(StorageAccessPreferences.DOWNLOADS).action)
    }
    @Test fun customFolderPickerUsesPersistableSafReadGrantAndEnforcesTenFolderLimit() {
        val picker = StorageAccessPreferences.pickerIntent(StorageAccessPreferences.CUSTOM)
        assertEquals(Intent.ACTION_OPEN_DOCUMENT_TREE, picker.action)
        assertTrue(picker.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
        assertTrue(picker.flags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION != 0)
        assertFalse(picker.hasExtra(android.provider.DocumentsContract.EXTRA_INITIAL_URI))
        assertEquals(10, StorageAccessPreferences.MAX_CUSTOM_FOLDERS)
    }
    @Test fun oldGrantIsRetainedAndRevokedGrantsDoNotCountAsCoverage() {
        val prefs = context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
        val old = prefs.getString("downloads_sentinel_tree_uri", null)
        val savedList = prefs.getString("sentinel_tree_uris_v2", null)
        try {
            prefs.edit().remove("sentinel_tree_uris_v2").putString("downloads_sentinel_tree_uri",
                "content://com.android.externalstorage.documents/tree/primary%3AOldFolder").commit()
            assertEquals(1, StorageAccessPreferences.selectedTreeUris(context).size)
            assertFalse(StorageAccessPreferences.hasAccess(context))
            prefs.edit().putString("sentinel_tree_uris_v2",
                "[\"content://com.android.externalstorage.documents/tree/primary%3AOne\",\"content://com.android.externalstorage.documents/tree/primary%3ATwo\"]").commit()
            StorageAccessPreferences.removeFolder(context, StorageAccessPreferences.selectedTreeUris(context).first())
            assertEquals(1, StorageAccessPreferences.selectedTreeUris(context).size)
            assertTrue(StorageAccessPreferences.selectedTreeUris(context).single().toString().endsWith("Two"))
        } finally { prefs.edit().putString("downloads_sentinel_tree_uri", old).putString("sentinel_tree_uris_v2", savedList).commit() }
    }
}
