package com.vibesync.antivirus.core.security

import android.Manifest
import android.content.ComponentName
import android.content.Context
import android.app.admin.DevicePolicyManager
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class NetworkPermissionBoundaryTest {
    @Test fun hashDatabaseSyncNeedsInternetButBroadStorageRemainsForbidden() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val info = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = info.requestedPermissions.orEmpty().toSet()
        assertTrue(Manifest.permission.INTERNET in requested)
        assertFalse(Manifest.permission.MANAGE_EXTERNAL_STORAGE in requested)
        assertFalse(Manifest.permission.READ_EXTERNAL_STORAGE in requested)
    }
    @Test fun overlaySpecialAccessAndDeviceAdminReceiverAreDeclared() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val packageInfo = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS)
        val requested = packageInfo.requestedPermissions.orEmpty().toSet()
        assertTrue(Manifest.permission.SYSTEM_ALERT_WINDOW in requested)

        val receiver = context.packageManager.getReceiverInfo(
            ComponentName(context, AdminReceiver::class.java),
            PackageManager.GET_META_DATA
        )
        assertEquals("android.permission.BIND_DEVICE_ADMIN", receiver.permission)
        assertTrue(receiver.enabled)
        assertTrue((receiver.metaData?.getInt("android.app.device_admin") ?: 0) != 0)
    }


    @Test fun deviceAdminActivationIntentTargetsTheDeclaredReceiver() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val request = DeviceAdminManager(context).buildAdminRequestIntent()
        assertEquals(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN, request.action)
        assertEquals(ComponentName(context, AdminReceiver::class.java),
            request.getParcelableExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, ComponentName::class.java))
        assertTrue(request.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
        assertTrue(request.getStringExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION).orEmpty().isNotBlank())
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
