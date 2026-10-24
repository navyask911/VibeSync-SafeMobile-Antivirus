package com.vibesync.antivirus.core.security

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OfflinePermissionBoundaryTest {
    @Test fun offlineVariantDoesNotRequestInternetOrBroadStorage() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions.orEmpty().toSet()
        assertFalse(Manifest.permission.INTERNET in requested)
        assertFalse(Manifest.permission.MANAGE_EXTERNAL_STORAGE in requested)
        assertFalse(Manifest.permission.READ_EXTERNAL_STORAGE in requested)
    }
    @Test fun appBackupFlagIsDisabled() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val info = context.packageManager.getApplicationInfo(context.packageName, 0)
        assertFalse(info.flags and ApplicationInfo.FLAG_ALLOW_BACKUP != 0)
    }
    @Test fun downloadMonitorHasNoAccessWithoutPersistedSelectedFolder() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE)
            .edit().remove("downloads_sentinel_tree_uri").commit()
        assertFalse(StorageAccessPreferences.hasAccess(context))
    }
}
