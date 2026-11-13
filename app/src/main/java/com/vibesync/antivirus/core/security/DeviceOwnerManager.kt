package com.vibesync.antivirus.core.security

import android.app.admin.DevicePolicyManager
import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Read-only status for devices provisioned with SafeMobile as a device owner.
 *
 * This does not request Device Admin, register a policy receiver, or attempt to become
 * a device/profile owner. Only Android's existing management state is queried.
 */
class DeviceOwnerManager(context: Context) {
    private val app = context.applicationContext
    private val _isDeviceOwner = MutableStateFlow(readOwnerState())
    val isDeviceOwner: StateFlow<Boolean> = _isDeviceOwner.asStateFlow()

    fun refreshState() {
        _isDeviceOwner.value = readOwnerState()
    }

    private fun readOwnerState(): Boolean = runCatching {
        val policyManager = app.getSystemService(DevicePolicyManager::class.java)
        policyManager?.isDeviceOwnerApp(app.packageName) == true
    }.getOrDefault(false)
}
