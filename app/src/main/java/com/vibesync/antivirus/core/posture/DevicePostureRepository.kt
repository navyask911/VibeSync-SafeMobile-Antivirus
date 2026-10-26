package com.vibesync.antivirus.core.posture

import android.content.Context
import com.vibesync.antivirus.SafeMobileApp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

data class PostureMonitorStatus(val enabled: Boolean, val lastCheckAt: Long, val storageError: Boolean, val pendingChanges: Int, val partial: Boolean)

/** Foreground audits never advance the comparison baseline or acknowledge pending notifications. */
class DevicePostureRepository(context: Context) {
    private val app = context.applicationContext
    private val inspector = DevicePostureInspector(app)
    private val store by lazy { EncryptedPostureSnapshotStore(app) }
    private val mutableReport = MutableStateFlow<DevicePostureReport?>(null)
    val report = mutableReport.asStateFlow()
    private val prefs get() = app.getSharedPreferences(DevicePostureMonitor.PREFS, Context.MODE_PRIVATE)

    fun consented() = app.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
        .getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)

    suspend fun refresh(): DevicePostureReport? = withContext(Dispatchers.IO) {
        if (!consented()) return@withContext null
        inspector.inspect().retainingUnavailable(mutableReport.value).also { mutableReport.value = it }
    }

    fun status() = PostureMonitorStatus(DevicePostureMonitor.isEnabled(app),
        prefs.getLong("last_check_at", 0L), prefs.getBoolean("storage_error", false), prefs.getInt("pending_count", 0), prefs.getBoolean("partial_check", false))

    /** The process-wide mutex serializes periodic/one-time workers over the same encrypted file. */
    suspend fun monitor(): Boolean = withContext(Dispatchers.IO) {
        monitorMutex.withLock {
            if (!consented() || !DevicePostureMonitor.isEnabled(app)) return@withLock true
            val observed = inspector.inspect(includeOverlay = false)
            val next = PostureMonitorComparison(store).check(observed) { change, finding ->
                PostureChangeNotifier.notify(app, change, finding)
            }
            val complete = (observed.unavailable intersect PostureSnapshotComparison.monitored).isEmpty()
            prefs.edit().putLong("last_check_at", next.lastCompleteCheckAt)
                .putBoolean("storage_error", false).putBoolean("partial_check", !complete).putInt("pending_count", next.pending.size).apply()
            complete
        }
    }

    fun reportStorageError() { prefs.edit().putBoolean("storage_error", true).apply() }
    companion object { private val monitorMutex = Mutex() }
}
