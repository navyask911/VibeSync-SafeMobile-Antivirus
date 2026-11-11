package com.vibesync.antivirus.core.security

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
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
        assertTrue(info.metaData?.containsKey("android.app.device_admin") == true)

        // Inspect the intent returned by the manager itself. This test does not launch an
        // activity or use Espresso Intents, so no unrelated navigation/permission intent
        // can be mistaken for the ACTION_ADD_DEVICE_ADMIN request.
        val activation = DeviceAdminManager(context).activationIntent()
        assertEquals(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN, activation.action)

        // API 26 uses the legacy Parcelable getter. Set the framework Parcelable loader
        // explicitly before reading the ComponentName, and report the complete captured
        // intent metadata if the extra is missing or cannot be decoded.
        activation.extras?.classLoader = AdminReceiver::class.java.classLoader
        val diagnostic = "action=${activation.action}, hasExtra=${activation.hasExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN)}, " +
            "extraKeys=${activation.extras?.keySet()}, extras=${activation.extras}"
        assertTrue(
            "ACTION_ADD_DEVICE_ADMIN must contain EXTRA_DEVICE_ADMIN; $diagnostic",
            activation.hasExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN)
        )

        val adminComponent = activation.getParcelableExtra<ComponentName>(
            DevicePolicyManager.EXTRA_DEVICE_ADMIN
        )
        assertNotNull("EXTRA_DEVICE_ADMIN must decode as ComponentName; $diagnostic", adminComponent)
        assertEquals(receiver, adminComponent)
        assertEquals(context.packageName, receiver.packageName)
    }
}
