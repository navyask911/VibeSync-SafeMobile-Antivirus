package com.vibesync.antivirus.presentation

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
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
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
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
internal fun SafeMobileSettingsPanel(
    privacyOptionsVisible: Boolean,
    onPrivacyOptionsClick: () -> Unit
) {
    val context = LocalContext.current
    val activity = context as? Activity
    val themePrefs = remember(context) { context.getSharedPreferences(AppearancePreferences.PREFS_NAME, Context.MODE_PRIVATE) }
    var themeMode by remember { mutableStateOf(themePrefs.getString(AppearancePreferences.THEME_KEY, "system") ?: "system") }
    var languageMenuExpanded by remember { mutableStateOf(false) }
    var localeOverrideTag by remember { mutableStateOf(LocalePreferences.overrideTag(context)) }
    var showAbout by remember { mutableStateOf(false) }
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
                Text(stringResource(R.string.not_configured), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
                if (privacyOptionsVisible) TextButton(onClick = onPrivacyOptionsClick) { Text(stringResource(R.string.privacy_options)) }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.about_legal), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text("SafeMobile Antivirus · ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})", style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { showAbout = true }) { Text(stringResource(R.string.about_legal)) }
            }
        }
    }

    if (showAbout) AlertDialog(
        onDismissRequest = { showAbout = false },
        title = { Text(stringResource(R.string.about_legal)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.privacy_body))
                Text(stringResource(R.string.scan_clean_warning))
                Text(stringResource(R.string.not_configured))
                Text(stringResource(R.string.license_review_pending))
            }
        },
        confirmButton = { TextButton(onClick = { showAbout = false }) { Text(stringResource(R.string.close)) } }
    )
}
