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
import androidx.compose.material3.Card
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
import com.vibesync.antivirus.core.worker.ThreatFeedFormat
import com.vibesync.antivirus.core.worker.ThreatFeedRequestMode
import com.vibesync.antivirus.core.worker.ThreatFeedUpdateMode
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.data.local.ScanAudit
import java.text.DateFormat
import java.util.Date
import java.util.UUID

internal object AppearancePreferences {
    const val PREFS_NAME = "safe_mobile_appearance"
    const val THEME_KEY = "theme_mode"
}

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
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* The review remains opt-in even when reminders are declined. */ }

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
                    OverlayRiskReviewManager.setEnabled(context, requested)
                    refreshFromPreferences()
                    if (requested && Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
                        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
                    ) {
                        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
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
}

@Composable
internal fun SafeMobileSettingsPanel(
    privacyOptionsVisible: Boolean,
    onPrivacyOptionsClick: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as? Activity
    val themePrefs = remember(context) { context.getSharedPreferences(AppearancePreferences.PREFS_NAME, Context.MODE_PRIVATE) }
    var themeMode by remember { mutableStateOf(themePrefs.getString(AppearancePreferences.THEME_KEY, "dark") ?: "dark") }
    var languageMenuExpanded by remember { mutableStateOf(false) }
    var localeOverrideTag by remember { mutableStateOf(LocalePreferences.overrideTag(context)) }
    var showAbout by remember { mutableStateOf(false) }
    var aboutSection by remember { mutableStateOf("privacy") }
    val rayId = remember(context) { InstallRayId.getOrCreate(context) }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.settings_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.appearance_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    FilterChip(
                        modifier = Modifier.fillMaxWidth(),
                        selected = themeMode == "system",
                        onClick = {
                            themeMode = "system"
                            themePrefs.edit().putString(AppearancePreferences.THEME_KEY, themeMode).apply()
                        },
                        label = { Text(stringResource(R.string.theme_system)) }
                    )
                    FilterChip(
                        modifier = Modifier.fillMaxWidth(),
                        selected = themeMode == "light",
                        onClick = {
                            themeMode = "light"
                            themePrefs.edit().putString(AppearancePreferences.THEME_KEY, themeMode).apply()
                        },
                        label = { Text(stringResource(R.string.theme_light)) }
                    )
                    FilterChip(
                        modifier = Modifier.fillMaxWidth(),
                        selected = themeMode == "dark",
                        onClick = {
                            themeMode = "dark"
                            themePrefs.edit().putString(AppearancePreferences.THEME_KEY, themeMode).apply()
                        },
                        label = { Text(stringResource(R.string.theme_dark)) }
                    )
                }
            }
        }
        OverlayRiskReviewPanel()

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
                if (privacyOptionsVisible) TextButton(onClick = onPrivacyOptionsClick) { Text(stringResource(R.string.privacy_options)) }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.about_legal), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text("SafeMobile Antivirus · " + BuildConfig.VERSION_NAME + " (" + BuildConfig.VERSION_CODE + ")", style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { showAbout = true }) { Text(stringResource(R.string.about_legal)) }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant), shape = RoundedCornerShape(18.dp)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.family_dedication_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.family_dedication), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

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


@Composable
internal fun ThreatFeedSettingsPanel() {
    val context = LocalContext.current
    val store = remember(context) { ThreatFeedConfigStore(context) }
    val initial = remember(store) { store.load() }
    var feedUrl by remember { mutableStateOf(initial.url) }
    var authKey by remember { mutableStateOf(initial.authKey) }
    var feedFormat by remember { mutableStateOf(initial.format) }
    var requestMode by remember { mutableStateOf(initial.requestMode) }
    var postJson by remember { mutableStateOf(initial.postJson) }
    var updateMode by remember { mutableStateOf(initial.updateMode) }
    var configured by remember { mutableStateOf(initial.url.isNotBlank()) }

    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.threat_feed_settings_title), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(stringResource(R.string.threat_feed_settings_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            OutlinedTextField(
                value = feedUrl,
                onValueChange = { feedUrl = it },
                label = { Text(stringResource(R.string.threat_feed_endpoint)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            OutlinedTextField(
                value = authKey,
                onValueChange = { authKey = it },
                label = { Text(stringResource(R.string.threat_feed_auth_key)) },
                supportingText = { Text(stringResource(R.string.threat_feed_credentials_note)) },
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Text(stringResource(R.string.threat_feed_method), style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = requestMode == ThreatFeedRequestMode.GET,
                    onClick = { requestMode = ThreatFeedRequestMode.GET },
                    label = { Text(stringResource(R.string.threat_feed_get)) }
                )
                FilterChip(
                    selected = requestMode == ThreatFeedRequestMode.POST_JSON,
                    onClick = { requestMode = ThreatFeedRequestMode.POST_JSON },
                    label = { Text(stringResource(R.string.threat_feed_post_json)) }
                )
            }
            if (requestMode == ThreatFeedRequestMode.POST_JSON) {
                OutlinedTextField(
                    value = postJson,
                    onValueChange = { postJson = it },
                    label = { Text(stringResource(R.string.threat_feed_post_body)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    maxLines = 5
                )
            }
            Text(stringResource(R.string.threat_feed_update_semantics), style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = updateMode == ThreatFeedUpdateMode.INCREMENTAL,
                    onClick = { updateMode = ThreatFeedUpdateMode.INCREMENTAL },
                    label = { Text(stringResource(R.string.threat_feed_incremental)) }
                )
                FilterChip(
                    selected = updateMode == ThreatFeedUpdateMode.AUTHORITATIVE_SNAPSHOT,
                    onClick = { updateMode = ThreatFeedUpdateMode.AUTHORITATIVE_SNAPSHOT },
                    label = { Text(stringResource(R.string.threat_feed_snapshot)) }
                )
            }
            Text(
                stringResource(R.string.threat_feed_update_semantics_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(stringResource(R.string.threat_feed_format), style = MaterialTheme.typography.labelLarge)
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(selected = feedFormat == ThreatFeedFormat.AUTO, onClick = { feedFormat = ThreatFeedFormat.AUTO }, label = { Text(stringResource(R.string.threat_feed_auto)) })
                FilterChip(selected = feedFormat == ThreatFeedFormat.JSON, onClick = { feedFormat = ThreatFeedFormat.JSON }, label = { Text(stringResource(R.string.threat_feed_json)) })
                FilterChip(selected = feedFormat == ThreatFeedFormat.CSV, onClick = { feedFormat = ThreatFeedFormat.CSV }, label = { Text(stringResource(R.string.threat_feed_csv)) })
            }
            Button(
                onClick = {
                    runCatching {
                        store.save(ThreatFeedConfiguration(feedUrl.trim(), authKey, feedFormat, requestMode, postJson, updateMode))
                        ThreatFeedSyncScheduler.ensurePeriodic(context)
                    }.onSuccess {
                        configured = true
                        Toast.makeText(context, R.string.threat_feed_saved, Toast.LENGTH_SHORT).show()
                    }.onFailure { error ->
                        Toast.makeText(context, error.message ?: context.getString(R.string.threat_feed_save_error), Toast.LENGTH_LONG).show()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.threat_feed_save)) }
            OutlinedButton(
                onClick = {
                    ThreatFeedSyncScheduler.enqueueNow(context)
                    Toast.makeText(context, R.string.threat_feed_queue_note, Toast.LENGTH_LONG).show()
                },
                enabled = configured,
                modifier = Modifier.fillMaxWidth()
            ) { Text(stringResource(R.string.threat_feed_sync_now)) }
            TextButton(onClick = {
                runCatching {
                    store.clear()
                    ThreatFeedSyncScheduler.ensurePeriodic(context)
                }.onSuccess {
                    feedUrl = ""
                    authKey = ""
                    feedFormat = ThreatFeedFormat.AUTO
                    requestMode = ThreatFeedRequestMode.GET
                    postJson = ThreatFeedConfiguration.DEFAULT_POST_JSON
                    updateMode = ThreatFeedUpdateMode.INCREMENTAL
                    configured = false
                    Toast.makeText(context, R.string.threat_feed_cleared, Toast.LENGTH_SHORT).show()
                }.onFailure {
                    Toast.makeText(context, R.string.threat_feed_save_error, Toast.LENGTH_LONG).show()
                }
            }) { Text(stringResource(R.string.threat_feed_clear)) }
        }
    }
}
