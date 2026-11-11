package com.vibesync.antivirus.core.security

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceAdminActivationTest {
    @Suppress("DEPRECATION")
    @Test
    fun activationIntentUsesDeclaredReceiverAndExactSystemAction() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val receiver = ComponentName(context, AdminReceiver::class.java)
        val info = context.packageManager.getReceiverInfo(receiver, PackageManager.GET_META_DATA)
        assertTrue(info.exported)
        assertEquals(android.Manifest.permission.BIND_DEVICE_ADMIN, info.permission)
        assertNotNull(info.metaData?.getInt("android.app.device_admin"))

        val activation = DeviceAdminManager(context).activationIntent()
        assertEquals(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN, activation.action)
        assertEquals(receiver, activation.getParcelableExtra<ComponentName>(DevicePolicyManager.EXTRA_DEVICE_ADMIN))
        assertEquals(context.packageName, receiver.packageName)
    }
}
