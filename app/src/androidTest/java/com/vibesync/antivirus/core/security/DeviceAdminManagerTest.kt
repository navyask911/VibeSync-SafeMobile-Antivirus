package com.vibesync.antivirus.core.security

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class DeviceAdminManagerTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun adminActivationIntentTargetsTheSystemDeviceAdminConfirmation() {
        val intent = DeviceAdminManager(context).createAdminRequestIntent(context)

        assertEquals(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN, intent.action)
        val component = intent.getParcelableExtra<ComponentName>(DevicePolicyManager.EXTRA_DEVICE_ADMIN)
        assertNotNull(component)
        assertEquals(AdminReceiver::class.java.name, component!!.className)
        assertNotNull(intent.getStringExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION))
    }
}
