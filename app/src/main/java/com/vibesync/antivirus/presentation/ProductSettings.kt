package com.vibesync.antivirus.presentation

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.selection.selectable
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.Alignment
import androidx.compose.material3.RadioButton
import com.vibesync.antivirus.ui.theme.AppTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import com.vibesync.antivirus.ui.components.CyberCard as Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Switch
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.app.NotificationManagerCompat
import com.vibesync.antivirus.core.worker.OverlayRiskReviewManager
import com.vibesync.antivirus.core.worker.ThreatFeedConfigStore
import com.vibesync.antivirus.core.worker.ThreatFeedConfiguration
import com.vibesync.antivirus.core.worker.ThreatFeedSyncScheduler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.observer.SecurityAlertNotifier
import com.vibesync.antivirus.core.observer.ThreatDetectedActivity
import android.content.Intent
import android.util.Log
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.data.local.ScanAudit
import java.text.DateFormat
import java.util.Date
import java.util.UUID

internal object InstallRayId {
    private const val PREFS_NAME = "safe_mobile_installation"
    private const val KEY = "ray_id"

    fun getOrCreate(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val existing = prefs.getString(KEY, null)
        if (!existing.isNullOrBlank()) return existing
        val generated = UUID.randomUUID().toString()
        prefs.edit().putString(KEY, generated).commit()
        return prefs.getString(KEY, generated) ?: generated
    }
}

@Composable
internal fun ScanHistoryPanel(audits: List<ScanAudit>) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.history_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        if (audits.isEmpty()) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Text(stringResource(R.string.history_empty), modifier = Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            val sessions = audits.groupBy { it.scanSessionId.ifBlank { "legacy-${it.id}" } }
                .values
                .sortedByDescending { group -> group.maxOfOrNull { it.scanTimestamp } ?: 0L }
                .take(30)
            sessions.forEach { group ->
                val mostRecent = group.maxByOrNull { it.scanTimestamp } ?: return@forEach
                val threats = group.count { it.verdict == "THREAT" }
                val review = group.count { it.verdict == "SUSPICIOUS" }
                val incomplete = group.count { it.verdict == "NOT_SCANNED" }
                Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                    Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                        Text(DateFormat.getDateTimeInstance().format(Date(mostRecent.scanTimestamp)), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                        Text(
                            stringResource(R.string.history_session) + ": " + (mostRecent.scanSessionId.ifBlank { "—" }),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            stringResource(
                                R.string.results_summary,
                                threats,
                                review,
                                group.count { it.verdict == "NO_MATCH" }
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        group.filter { it.threatEventId.isNotBlank() && it.verdict == "THREAT" }.forEach { event ->
                            Text(
                                stringResource(R.string.threat_event_ray_id, event.threatEventId),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        if (incomplete > 0) {
                            Text(
                                "${stringResource(R.string.verdict_not_scanned)}: $incomplete",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.tertiary
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun OverlayRiskReviewPanel() {
    val context = LocalContext.current
    val prefs = remember(context) {
        context.getSharedPreferences(OverlayRiskReviewManager.PREFS_NAME, Context.MODE_PRIVATE)
    }
    var enabled by remember { mutableStateOf(OverlayRiskReviewManager.isEnabled(context)) }
    var lastAttempt by remember { mutableStateOf(prefs.getLong(OverlayRiskReviewManager.KEY_LAST_ATTEMPT, 0L)) }
    var lastSuccess by remember { mutableStateOf(prefs.getLong(OverlayRiskReviewManager.KEY_LAST_SUCCESS, 0L)) }
    var overlayDeclarations by remember { mutableStateOf(prefs.getInt(OverlayRiskReviewManager.KEY_OVERLAY_DECLARATIONS, 0)) }
    var accessibilityDeclarations by remember { mutableStateOf(prefs.getInt(OverlayRiskReviewManager.KEY_ACCESSIBILITY_DECLARATIONS, 0)) }
    var enabledServices by remember { mutableStateOf(prefs.getInt(OverlayRiskReviewManager.KEY_ENABLED_ACCESSIBILITY_SERVICES, 0)) }
    var resultState by remember { mutableStateOf(prefs.getString(OverlayRiskReviewManager.KEY_RESULT, "NOT_CHECKED") ?: "NOT_CHECKED") }
    var reminderHours by remember { mutableStateOf(prefs.getInt(OverlayRiskReviewManager.KEY_REMINDER_HOURS, 24)) }
    var intervalMenuExpanded by remember { mutableStateOf(false) }
    var showNotificationPermissionPrompt by remember { mutableStateOf(false) }
    var pendingReviewEnable by remember { mutableStateOf(false) }
    fun refreshFromPreferences() {
        enabled = OverlayRiskReviewManager.isEnabled(context)
        lastAttempt = prefs.getLong(OverlayRiskReviewManager.KEY_LAST_ATTEMPT, 0L)
        lastSuccess = prefs.getLong(OverlayRiskReviewManager.KEY_LAST_SUCCESS, 0L)
        overlayDeclarations = prefs.getInt(OverlayRiskReviewManager.KEY_OVERLAY_DECLARATIONS, 0)
        accessibilityDeclarations = prefs.getInt(OverlayRiskReviewManager.KEY_ACCESSIBILITY_DECLARATIONS, 0)
        enabledServices = prefs.getInt(OverlayRiskReviewManager.KEY_ENABLED_ACCESSIBILITY_SERVICES, 0)
        resultState = prefs.getString(OverlayRiskReviewManager.KEY_RESULT, "NOT_CHECKED") ?: "NOT_CHECKED"
        reminderHours = prefs.getInt(OverlayRiskReviewManager.KEY_REMINDER_HOURS, 24)
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (pendingReviewEnable) {
            OverlayRiskReviewManager.setEnabled(context, granted)
            pendingReviewEnable = false
            refreshFromPreferences()
        }
    }
    DisposableEffect(prefs) {
        val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, _ ->
            refreshFromPreferences()
        }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        onDispose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    val notificationsAvailable =
        (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) &&
            NotificationManagerCompat.from(context).areNotificationsEnabled()

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            androidx.compose.foundation.layout.Row(
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(stringResource(R.string.overlay_review_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(stringResource(if (enabled) R.string.overlay_review_enabled else R.string.overlay_review_disabled), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(checked = enabled, onCheckedChange = { requested ->
                    if (!requested) {
                        OverlayRiskReviewManager.setEnabled(context, false)
                        refreshFromPreferences()
                    } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                    ) {
                        pendingReviewEnable = true
                        showNotificationPermissionPrompt = true
                    } else {
                        OverlayRiskReviewManager.setEnabled(context, true)
                        refreshFromPreferences()
                    }
                })
            }
            Text(stringResource(R.string.overlay_review_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (lastAttempt > 0L) {
                Text(
                    stringResource(R.string.overlay_review_last_attempt, DateFormat.getDateTimeInstance().format(Date(lastAttempt))),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (lastSuccess > 0L) {
                Text(
                    stringResource(R.string.overlay_review_last_success, DateFormat.getDateTimeInstance().format(Date(lastSuccess))),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    stringResource(R.string.overlay_review_summary, overlayDeclarations, accessibilityDeclarations, enabledServices),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
            } else {
                Text(
                    when (resultState) {
                        "FAILED" -> stringResource(R.string.overlay_review_failed)
                        "PERMISSION_REQUIRED" -> stringResource(R.string.overlay_review_permission_required)
                        else -> stringResource(R.string.overlay_review_not_checked)
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }
            androidx.compose.material3.TextButton(
                onClick = { intervalMenuExpanded = true },
                enabled = enabled
            ) {
                Text(
                    stringResource(R.string.overlay_review_reminder_interval) + ": " +
                        stringResource(
                            when (reminderHours) {
                                12 -> R.string.overlay_review_reminder_12h
                                48 -> R.string.overlay_review_reminder_48h
                                else -> R.string.overlay_review_reminder_24h
                            }
                        )
                )
            }
            DropdownMenu(expanded = intervalMenuExpanded, onDismissRequest = { intervalMenuExpanded = false }) {
                listOf(
                    12 to R.string.overlay_review_reminder_12h,
                    24 to R.string.overlay_review_reminder_24h,
                    48 to R.string.overlay_review_reminder_48h
                ).forEach { (hours, label) ->
                    DropdownMenuItem(
                        text = { Text(stringResource(label)) },
                        onClick = {
                            OverlayRiskReviewManager.setReminderIntervalHours(context, hours)
                            intervalMenuExpanded = false
                            refreshFromPreferences()
                        }
                    )
                }
            }
            if (enabled && !notificationsAvailable) {
                Text(stringResource(R.string.overlay_review_notifications_off), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
    if (showNotificationPermissionPrompt) AlertDialog(
        onDismissRequest = {
            showNotificationPermissionPrompt = false
            pendingReviewEnable = false
        },
        title = { Text(stringResource(R.string.overlay_review_title)) },
        text = { Text(stringResource(R.string.overlay_review_description)) },
        confirmButton = {
            TextButton(onClick = {
                showNotificationPermissionPrompt = false
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }) { Text(stringResource(R.string.setup_allow_notifications)) }
        },
        dismissButton = {
            TextButton(onClick = {
                showNotificationPermissionPrompt = false
                pendingReviewEnable = false
            }) { Text(stringResource(R.string.setup_notifications_not_now)) }
        }
    )
}

@Composable
internal fun SafeMobileSettingsPanel(
    sentinelEnabled: Boolean,
    onEnableSentinel: () -> Unit,
    onDisableSentinel: () -> Unit,
    strictMode: Boolean = false,
    securityAlertsEnabled: Boolean = false,
    onSecurityAlertsChanged: ((Boolean) -> Unit)? = null,
    onToggleProtection: ((Boolean) -> Unit)? = null,
    onStrictModeChanged: ((Boolean) -> Unit)? = null,
    appTheme: AppTheme = AppTheme.MIDNIGHT,
    onAppThemeChanged: (AppTheme) -> Unit = {}
) {
    val context = LocalContext.current
    val activity = context as? Activity
    var languageMenuExpanded by remember { mutableStateOf(false) }
    var localeOverrideTag by remember { mutableStateOf(LocalePreferences.overrideTag(context)) }
    var showAbout by remember { mutableStateOf(false) }
    var aboutSection by remember { mutableStateOf("privacy") }
    val rayId = remember(context) { InstallRayId.getOrCreate(context) }
    val feedStore = remember(context) { ThreatFeedConfigStore(context) }
    var feedUrl by remember { mutableStateOf(feedStore.load().url) }
    var feedAuthKey by remember { mutableStateOf(feedStore.load().authKey) }
    var feedConfigSaved by remember { mutableStateOf(feedStore.isConfigured()) }
    var feedConsentEnabled by remember { mutableStateOf(feedStore.isSyncEnabled()) }
    var feedConfigMessage by remember { mutableStateOf<String?>(null) }
    var showFeedConsentDialog by remember { mutableStateOf(false) }
    var showFullScreenPrompt by remember { mutableStateOf(false) }
    val voicePrefs = remember(context) { context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE) }
    var voiceAlertsEnabled by remember(context) { mutableStateOf(voicePrefs.getBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, false)) }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.appearance_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.theme_appearance_description),
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                for (option in AppTheme.entries) {
                    val label = when (option) {
                        AppTheme.MIDNIGHT -> R.string.theme_midnight
                        AppTheme.LIGHT -> R.string.theme_light
                        AppTheme.OLED -> R.string.theme_oled
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth().selectable(
                            selected = appTheme == option,
                            role = Role.RadioButton,
                            onClick = { onAppThemeChanged(option) }
                        ).padding(vertical = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        RadioButton(selected = appTheme == option, onClick = null)
                        Text(stringResource(label), color = MaterialTheme.colorScheme.onSurface)
                    }
                }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.siren_test_settings_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.siren_test_settings_description), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = {
                    // Explicit user-initiated demo; never inserts a fabricated malware record.
                    val eventId = SecurityAlertNotifier.runManualSirenTest(context)
                    val preview = Intent(context, ThreatDetectedActivity::class.java)
                        .putExtra(SecurityAlertNotifier.EXTRA_TEST_MODE, true)
                        .putExtra("security.incident.event_id", eventId)
                    runCatching { context.startActivity(preview) }
                        .onFailure { Log.w("SafeMobileSiren", "Manual siren preview unavailable", it) }
                }) { Text(stringResource(R.string.siren_test_button)) }
            }
        }
        InstallSentinelSettings()
        OverlayRiskReviewPanel()

        if (BuildConfig.OPTIONAL_FEED_ENABLED) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(stringResource(R.string.feed_settings_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text(stringResource(R.string.feed_settings_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedTextField(
                        value = feedUrl,
                        onValueChange = { feedUrl = it; feedConfigSaved = false },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text(stringResource(R.string.feed_settings_url_label)) },
                        placeholder = { Text("https://example.invalid/feed.json") }
                    )
                    OutlinedTextField(
                        value = feedAuthKey,
                        onValueChange = { feedAuthKey = it; feedConfigSaved = false },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        visualTransformation = PasswordVisualTransformation(),
                        label = { Text(stringResource(R.string.feed_settings_auth_label)) }
                    )
                    Button(onClick = {
                        runCatching {
                            feedStore.save(feedStore.load().copy(url = feedUrl, authKey = feedAuthKey))
                        }.onSuccess {
                            feedConfigSaved = feedStore.isConfigured()
                            feedConfigMessage = context.getString(R.string.feed_settings_saved)
                            ThreatFeedSyncScheduler.ensurePeriodic(context)
                        }.onFailure {
                            feedConfigMessage = it.message ?: context.getString(R.string.feed_settings_failed)
                        }
                    }) { Text(stringResource(R.string.feed_settings_save)) }
                    feedConfigMessage?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    Text(
                        stringResource(
                            if (BuildConfig.FEED_MANIFEST_KEY_CONFIGURED) R.string.feed_settings_key_ready
                            else R.string.feed_settings_key_missing
                        ),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(stringResource(R.string.feed_settings_opt_in_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                            Text(stringResource(R.string.feed_settings_opt_in_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        Switch(
                            checked = feedConsentEnabled,
                            enabled = BuildConfig.FEED_MANIFEST_KEY_CONFIGURED && feedConfigSaved && feedUrl.isNotBlank(),
                            onCheckedChange = { requested ->
                                if (requested) showFeedConsentDialog = true
                                else {
                                    feedStore.setSyncEnabled(false)
                                    feedConsentEnabled = false
                                    ThreatFeedSyncScheduler.ensurePeriodic(context)
                                    feedConfigMessage = context.getString(R.string.feed_settings_disabled)
                                }
                            }
                        )
                    }
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.download_interceptor_label), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.download_interceptor_description), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(
                    stringResource(if (sentinelEnabled) R.string.download_interceptor_status_enabled else R.string.download_interceptor_status_setup),
                    style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(stringResource(if (sentinelEnabled) R.string.download_sentinel_running else R.string.download_sentinel_stopped),
                        style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    Switch(checked = sentinelEnabled, onCheckedChange = { enabled ->
                        if (onToggleProtection != null) onToggleProtection.invoke(enabled)
                        else if (enabled) onEnableSentinel() else onDisableSentinel()
                    })
                }
                Text(stringResource(R.string.security_alerts_title), style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.incident_alerts_explanation), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(stringResource(if (securityAlertsEnabled) R.string.security_alerts_enabled else R.string.security_alerts_disabled),
                        modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = securityAlertsEnabled, onCheckedChange = { onSecurityAlertsChanged?.invoke(it) })
                }
                if (securityAlertsEnabled && Build.VERSION.SDK_INT >= 34) {
                    OutlinedButton(onClick = { showFullScreenPrompt = true }, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.incident_full_screen_settings))
                    }
                }
                Text(stringResource(R.string.strict_mode_description), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(stringResource(R.string.strict_mode_label), modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                    Switch(checked = strictMode, onCheckedChange = { onStrictModeChanged?.invoke(it) })
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.voice_alerts_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.voice_alerts_description), style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(Modifier.fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(
                        stringResource(if (voiceAlertsEnabled) R.string.voice_alerts_enabled else R.string.voice_alerts_disabled),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.weight(1f)
                    )
                    Switch(
                        checked = voiceAlertsEnabled,
                        onCheckedChange = { enabled ->
                            voiceAlertsEnabled = enabled
                            voicePrefs.edit().putBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, enabled).apply()
                        }
                    )
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.language_settings), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    if (localeOverrideTag.isBlank()) stringResource(R.string.language_system_default)
                    else stringResource(LocalePreferences.labelResource(localeOverrideTag)),
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                TextButton(onClick = { languageMenuExpanded = true }) { Text(stringResource(R.string.language_settings)) }
                DropdownMenu(expanded = languageMenuExpanded, onDismissRequest = { languageMenuExpanded = false }) {
                    DropdownMenuItem(
                        text = { Text(stringResource(R.string.language_system_default)) },
                        onClick = {
                            LocalePreferences.saveOverride(context, "")
                            localeOverrideTag = ""
                            languageMenuExpanded = false
                            activity?.recreate()
                        }
                    )
                    LocalePreferences.choices.forEach { choice ->
                        DropdownMenuItem(
                            text = { Text(stringResource(choice.labelResource)) },
                            onClick = {
                                LocalePreferences.saveOverride(context, choice.tag)
                                localeOverrideTag = choice.tag
                                languageMenuExpanded = false
                                activity?.recreate()
                            }
                        )
                    }
                }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.ray_id), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(rayId, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = {
                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                    clipboard?.setPrimaryClip(ClipData.newPlainText("SafeMobile Ray ID", rayId))
                    Toast.makeText(context, R.string.ray_id_copied, Toast.LENGTH_SHORT).show()
                }) { Text(stringResource(R.string.ray_id_copy)) }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.settings_privacy), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.privacy_body), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.about_legal), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.brand_title) + " · " + BuildConfig.VERSION_NAME + " (" + BuildConfig.VERSION_CODE + ")", style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { showAbout = true }) { Text(stringResource(R.string.about_legal)) }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), shape = RoundedCornerShape(16.dp)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.family_dedication_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.family_dedication), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

    if (showFullScreenPrompt && Build.VERSION.SDK_INT >= 34) AlertDialog(
        onDismissRequest = { showFullScreenPrompt = false },
        title = { Text(stringResource(R.string.incident_full_screen_settings)) },
        text = { Text(stringResource(R.string.incident_full_screen_explanation)) },
        confirmButton = { TextButton(onClick = {
            showFullScreenPrompt = false
            runCatching {
                context.startActivity(android.content.Intent(android.provider.Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT,
                    android.net.Uri.fromParts("package", context.packageName, null)))
            }.onFailure { Toast.makeText(context, R.string.uninstall_no_settings, Toast.LENGTH_LONG).show() }
        }) { Text(stringResource(R.string.incident_open_settings)) } },
        dismissButton = { TextButton(onClick = { showFullScreenPrompt = false }) {
            Text(stringResource(R.string.setup_notifications_not_now))
        } }
    )

    if (showFeedConsentDialog) AlertDialog(
        onDismissRequest = { showFeedConsentDialog = false },
        title = { Text(stringResource(R.string.feed_settings_consent_title)) },
        text = { Text(stringResource(R.string.feed_settings_consent_body)) },
        confirmButton = {
            TextButton(onClick = {
                feedStore.setSyncEnabled(true)
                feedConsentEnabled = true
                showFeedConsentDialog = false
                ThreatFeedSyncScheduler.ensurePeriodic(context)
                ThreatFeedSyncScheduler.enqueueNow(context)
                feedConfigMessage = context.getString(R.string.feed_settings_enabled)
            }) { Text(stringResource(R.string.feed_settings_confirm)) }
        },
        dismissButton = {
            TextButton(onClick = { showFeedConsentDialog = false }) {
                Text(stringResource(R.string.feed_settings_cancel))
            }
        }
    )

    val aboutContent = remember(context, aboutSection) {
        when (aboutSection) {
            "readme" -> runCatching { context.assets.open("README.md").bufferedReader().use { it.readText() } }.getOrDefault("Bundled README is unavailable.").let { readme -> "$readme\n\n${context.getString(R.string.features_disclaimer)}\n\n${context.getString(R.string.not_configured)}" }
            "notices" -> runCatching { context.assets.open("THIRD_PARTY_NOTICES.md").bufferedReader().use { it.readText() } }.getOrDefault("Third-party licence notices are unavailable.")
            "license" -> context.getString(R.string.about_license_missing)
            else -> runCatching { context.assets.open("privacy-policy.md").bufferedReader().use { it.readText() } }.getOrDefault(context.getString(R.string.privacy_body))
        }
    }
    if (showAbout) AlertDialog(
        onDismissRequest = { showAbout = false },
        title = { Text(stringResource(R.string.about_legal)) },
        text = {
            Column(
                Modifier.fillMaxWidth().heightIn(max = 470.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    TextButton(onClick = { aboutSection = "readme" }) { Text(stringResource(R.string.about_readme)) }
                    TextButton(onClick = { aboutSection = "privacy" }) { Text(stringResource(R.string.about_privacy_policy)) }
                }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                    TextButton(onClick = { aboutSection = "license" }) { Text(stringResource(R.string.about_license)) }
                    TextButton(onClick = { aboutSection = "notices" }) { Text(stringResource(R.string.about_third_party)) }
                }
                Text(aboutContent, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurface)
            }
        },
        confirmButton = { TextButton(onClick = { showAbout = false }) { Text(stringResource(R.string.close)) } }
    )
}

