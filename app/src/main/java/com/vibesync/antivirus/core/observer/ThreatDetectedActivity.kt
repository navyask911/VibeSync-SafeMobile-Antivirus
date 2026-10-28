package com.vibesync.antivirus.core.observer

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.animateColor
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Icon
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.OutlinedButton
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.graphics.drawable.toBitmap
import androidx.lifecycle.lifecycleScope
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.presentation.SystemPackageGuard
import com.vibesync.antivirus.presentation.UninstallHandler
import com.vibesync.antivirus.presentation.UninstallResult
import com.vibesync.antivirus.ui.components.GlassCard
import com.vibesync.antivirus.ui.theme.SafeMobileMaterialTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** An internal notification destination. It never starts an uninstaller until the user taps. */
class ThreatDetectedActivity : ComponentActivity() {
    private data class AppPresentation(val packageName: String, val label: String, val icon: ImageBitmap?)
    private var target by mutableStateOf<AppPresentation?>(null)
    private var loading by mutableStateOf(true)
    private var eventId: String? = null
    private var manualTest by mutableStateOf(false)
    private var trusted by mutableStateOf(false)
    private var requestGeneration = 0

    override fun attachBaseContext(newBase: Context) { super.attachBaseContext(LocalePreferences.wrap(newBase)) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(statusBarStyle = androidx.activity.SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = androidx.activity.SystemBarStyle.dark(android.graphics.Color.rgb(15, 23, 42)))
        if (Build.VERSION.SDK_INT >= 27) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)
        }
        loadIncident(intent)
        setContent {
            SafeMobileMaterialTheme {
                BackHandler { dismissIncident() }
                val pulse = rememberInfiniteTransition()
                // A slow red pulse, below strobe frequencies; text remains visible throughout.
                val red by pulse.animateColor(Color(0xFFB91C1C), Color(0xFFEF4444),
                    infiniteRepeatable(tween(1_000), RepeatMode.Reverse))
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    Column(Modifier.safeDrawingPadding().verticalScroll(rememberScrollState()).padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(stringResource(if (manualTest) R.string.siren_test_title else if (trusted) R.string.trusted_app_saved else R.string.incident_title), style = MaterialTheme.typography.headlineLarge,
                            color = MaterialTheme.colorScheme.error, fontWeight = FontWeight.Bold)
                        GlassCard(Modifier.fillMaxWidth()) {
                            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                target?.icon?.let { Image(it, contentDescription = null, modifier = Modifier.size(72.dp)) }
                                if (manualTest) {
                                    Text(stringResource(R.string.siren_test_preview), style = MaterialTheme.typography.titleMedium)
                                } else {
                                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                        Text(target?.label ?: stringResource(if (loading) R.string.incident_loading else R.string.incident_app_unavailable),
                                            modifier = Modifier.weight(1f), style = MaterialTheme.typography.titleLarge)
                                        if (trusted) target?.let { app -> TrustedIncidentOptions(app.packageName) }
                                    }
                                    target?.let { Text(it.packageName, style = MaterialTheme.typography.bodySmall) }
                                    Text(stringResource(if (trusted) R.string.trusted_app_explanation else R.string.incident_warning), color = MaterialTheme.colorScheme.onSurface)
                                }
                            }
                        }
                        if (!manualTest && !trusted) {
                            Button(onClick = ::requestUninstall, enabled = target != null,
                                colors = ButtonDefaults.buttonColors(containerColor = red, contentColor = MaterialTheme.colorScheme.onError),
                                modifier = Modifier.fillMaxWidth().heightIn(min = 96.dp)) {
                                Text(stringResource(R.string.incident_uninstall_now), style = MaterialTheme.typography.headlineSmall,
                                    fontWeight = FontWeight.ExtraBold)
                            }
                        }
                        OutlinedButton(onClick = ::dismissIncident, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
                            Text(stringResource(R.string.incident_dismiss))
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        loadIncident(intent)
    }

    private fun loadIncident(intent: Intent) {
        eventId = intent.getStringExtra(SecurityAlertNotifier.EXTRA_EVENT_ID)
        manualTest = intent.getBooleanExtra(SecurityAlertNotifier.EXTRA_TEST_MODE, false)
        trusted = false
        if (manualTest) { target = null; loading = false; return }
        val name = SystemPackageGuard.normalizePackageName(intent.getStringExtra(EXTRA_PACKAGE))
        val generation = ++requestGeneration
        target = null
        loading = true
        lifecycleScope.launch {
            val app = withContext(Dispatchers.IO) {
                runCatching {
                    if (name == null || !SystemPackageGuard.isUserInstalled(this@ThreatDetectedActivity, name)) return@runCatching null
                    @Suppress("DEPRECATION")
                    val info = packageManager.getApplicationInfo(name, 0)
                    AppPresentation(name, packageManager.getApplicationLabel(info).toString().take(160),
                        runCatching { packageManager.getApplicationIcon(info).toBitmap(144, 144).asImageBitmap() }.getOrNull())
                }.getOrNull()
            }
            val trustedNow = withContext(Dispatchers.IO) {
                name?.let { com.vibesync.antivirus.core.security.TrustedAppStore(this@ThreatDetectedActivity).isTrusted(it) } == true
            }
            if (generation == requestGeneration) { target = app; trusted = trustedNow; loading = false }
        }
    }

    @androidx.compose.runtime.Composable
    private fun TrustedIncidentOptions(packageName: String) {
        var expanded by androidx.compose.runtime.remember { mutableStateOf(false) }
        androidx.compose.foundation.layout.Box {
            androidx.compose.material3.IconButton(onClick = { expanded = true }) {
                Icon(Icons.Default.MoreVert, contentDescription = stringResource(R.string.trusted_app_options))
            }
            androidx.compose.material3.DropdownMenu(expanded, onDismissRequest = { expanded = false }) {
                androidx.compose.material3.DropdownMenuItem(text = { Text(stringResource(R.string.uninstall_label)) },
                    onClick = { expanded = false; requestUninstall() })
                androidx.compose.material3.DropdownMenuItem(text = { Text(stringResource(R.string.trusted_app_remove)) },
                    onClick = {
                        expanded = false
                        lifecycleScope.launch {
                            try {
                                withContext(Dispatchers.IO) { com.vibesync.antivirus.core.security.TrustedAppStore(this@ThreatDetectedActivity).untrust(packageName) }
                                trusted = false
                            } catch (cancelled: kotlinx.coroutines.CancellationException) { throw cancelled }
                            catch (_: Exception) { Toast.makeText(this@ThreatDetectedActivity, R.string.trusted_app_remove_failed, Toast.LENGTH_LONG).show() }
                        }
                    })
            }
        }
    }

    private fun requestUninstall() {
        SecurityAlertNotifier.dismiss(this, eventId)
        val name = target?.packageName ?: return
        // Re-check system/admin protections immediately before opening Android's confirmation UI.
        val result = runCatching { UninstallHandler.request(this, name,
            launchDelete = { startActivity(it) }, openAppInfo = { startActivity(it) }) }.getOrNull()
        if (result !is UninstallResult.RequiresUserAction && result !is UninstallResult.OpenedAppInfo) {
            Toast.makeText(this, R.string.uninstall_protected, Toast.LENGTH_LONG).show()
        }
    }

    private fun dismissIncident() { SecurityAlertNotifier.dismiss(this, eventId); finish() }

    override fun onUserLeaveHint() {
        SecurityAlertNotifier.stopIncidentAudio()
        super.onUserLeaveHint()
    }

    override fun onDestroy() {
        if (isFinishing) SecurityAlertNotifier.stopIncidentAudio()
        super.onDestroy()
    }

    companion object { internal const val EXTRA_PACKAGE = "security.incident.package" }
}
