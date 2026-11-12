package com.vibesync.antivirus.presentation

import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.core.app.ActivityOptionsCompat

/**
 * Paparazzi snapshots do not run inside a ComponentActivity. Supply a no-op
 * registry so Compose launchers can register during rendering without
 * launching Android UI or depending on Google Play services.
 */
internal class SnapshotActivityResultRegistryOwner : ActivityResultRegistryOwner {
    override val activityResultRegistry: ActivityResultRegistry =
        object : ActivityResultRegistry() {
            override fun <I, O> onLaunch(
                requestCode: Int,
                contract: ActivityResultContract<I, O>,
                input: I,
                options: ActivityOptionsCompat?
            ) = Unit
        }
}
