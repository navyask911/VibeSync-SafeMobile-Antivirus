package com.vibesync.antivirus.core.observer

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.vibesync.antivirus.MainActivity
import com.vibesync.antivirus.R
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.core.worker.PostInstallScanProcessor
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Idle receiver with one serial event queue: no polling, timers, network or wake lock. */
class InstallSentinelService : Service() {
    private data class Install(val name: String, val eventId: String, val updated: Boolean)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val pending = Channel<Install>(32)
    private var receiver: PackageInstallReceiver? = null

    override fun attachBaseContext(newBase: Context) { super.attachBaseContext(LocalePreferences.wrap(newBase)) }

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL,
            getString(R.string.install_sentinel_title), NotificationManager.IMPORTANCE_LOW).apply {
            setSound(null, null); enableVibration(false)
        })
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, InstallSentinelService::class.java).setAction(STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = NotificationCompat.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_launcher)
            .setContentTitle(getString(R.string.install_sentinel_active))
            .setContentText(getString(R.string.install_sentinel_description)).setContentIntent(open)
            .setOngoing(true).setSilent(true).setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE).setPriority(NotificationCompat.PRIORITY_LOW)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .addAction(0, getString(R.string.install_sentinel_stop), stop).build()
        ServiceCompat.startForeground(this, ID, notification,
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0)
        if (!enabled(this)) { stopSelf(); return }
        val liveReceiver = PackageInstallReceiver { name, eventId, updated ->
            pending.trySend(Install(name, eventId, updated)).isSuccess
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED); addAction(Intent.ACTION_PACKAGE_REPLACED); addDataScheme("package")
        }
        ContextCompat.registerReceiver(this, liveReceiver, filter, ContextCompat.RECEIVER_EXPORTED)
        receiver = liveReceiver
        active.value = true
        Log.e(TAG, "Foreground install sentinel active; protected package receiver registered")
        scope.launch {
            for (install in pending) {
                try { PostInstallScanProcessor.scan(applicationContext, install.name, install.eventId, install.updated) }
                catch (cancelled: CancellationException) { throw cancelled }
                catch (error: Exception) { Log.e(TAG, "Live scan failed; durable work remains queued", error) }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) getSharedPreferences(SafeMobileApp.SECURITY_PREFS, MODE_PRIVATE)
            .edit().putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, false).apply()
        if (!enabled(this)) { stopSelf(startId); return START_NOT_STICKY }
        return START_STICKY
    }

    override fun onDestroy() {
        receiver?.let { runCatching { unregisterReceiver(it) } }
        receiver = null
        active.value = false
        pending.close()
        scope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        Log.d(TAG, "Install sentinel stopped")
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    companion object {
        private const val TAG = "SafeMobileInstallSentinel"
        private const val CHANNEL = "install_sentinel_service_v1"
        private const val ID = 2_100_001
        private const val STOP = "com.vibesync.antivirus.STOP_INSTALL_SENTINEL"
        private val active = MutableStateFlow(false)
        val running = active.asStateFlow()

        fun enabled(context: Context): Boolean =
            context.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, MODE_PRIVATE)
                .getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false) &&
            context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, MODE_PRIVATE)
                .getBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, true)

        /** Called while the activity is visible, never from Application/WorkManager startup. */
        fun startFromVisibleUi(context: Context): Boolean {
            if (!enabled(context)) return false
            return runCatching {
                ContextCompat.startForegroundService(context, Intent(context, InstallSentinelService::class.java))
                true
            }.onFailure { Log.e(TAG, "Android denied foreground sentinel startup", it) }.getOrDefault(false)
        }

        fun stop(context: Context) {
            context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, MODE_PRIVATE).edit()
                .putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, false).apply()
            context.stopService(Intent(context, InstallSentinelService::class.java))
        }
    }
}
