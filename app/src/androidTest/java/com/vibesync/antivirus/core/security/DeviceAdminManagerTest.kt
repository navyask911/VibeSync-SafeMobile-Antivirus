package com.vibesync.antivirus.core.security

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.view.ContextThemeWrapper
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class DeviceAdminManagerTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun adminActivationIntentTargetsTheSystemDeviceAdminConfirmation() {
        // Compose commonly supplies a ContextThemeWrapper rather than an Activity.
        // Intent construction must work without an Activity cast or startActivity call.
        val themedContext = ContextThemeWrapper(context, com.vibesync.antivirus.R.style.Theme_SafeMobile)
        val intent = DeviceAdminManager(themedContext).createAdminRequestIntent(themedContext)

        assertEquals(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN, intent.action)
        val component = intent.getParcelableExtra<ComponentName>(DevicePolicyManager.EXTRA_DEVICE_ADMIN)
        assertNotNull(component)
        assertEquals(AdminReceiver::class.java.name, component!!.className)
        assertNotNull(intent.getStringExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION))
    }
}
