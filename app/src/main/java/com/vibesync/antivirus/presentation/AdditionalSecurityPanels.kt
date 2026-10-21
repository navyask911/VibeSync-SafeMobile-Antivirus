package com.vibesync.antivirus.presentation

import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.DocumentsContract
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.data.local.MalwareHashEntity
import com.vibesync.antivirus.data.repository.ThreatRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.IDN
import java.net.URI
import java.util.Locale

@Composable
internal fun CoreStrengthsAccordion(onNavigate: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            TextButton(onClick = { expanded = !expanded }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(22.dp))
                Text(
                    stringResource(R.string.why_safemobile),
                    modifier = Modifier.weight(1f).padding(start = 8.dp),
                    fontWeight = FontWeight.Bold
                )
                Text(if (expanded) "−" else "+")
            }
            if (expanded) {
                Text(stringResource(R.string.features_disclaimer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                FeatureRow(Icons.Default.CloudOff, R.string.pillar_offline_title, R.string.pillar_offline_body, R.string.feature_status_limited) { onNavigate("scan") }
                FeatureRow(Icons.Default.Security, R.string.pillar_telemetry_title, R.string.pillar_telemetry_body, R.string.feature_status_local) { onNavigate("settings") }
                FeatureRow(Icons.Default.Security, R.string.pillar_whatsapp_title, R.string.pillar_whatsapp_body, R.string.feature_status_limited) { onNavigate("scan") }
                FeatureRow(Icons.Default.Link, R.string.pillar_phishing_title, R.string.pillar_phishing_body, R.string.feature_status_heuristic) { onNavigate("phishing") }
                FeatureRow(Icons.Default.DeleteSweep, R.string.pillar_cleaner_title, R.string.pillar_cleaner_body, R.string.feature_status_review) { onNavigate("cleaner") }
            }
        }
    }
}

@Composable
private fun FeatureRow(
    image: androidx.compose.ui.graphics.vector.ImageVector,
    titleResource: Int,
    bodyResource: Int,
    statusResource: Int,
    onClick: () -> Unit
) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(image, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
                Text(
                    stringResource(titleResource),
                    modifier = Modifier.weight(1f).padding(start = 8.dp),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
            }
            Text(stringResource(bodyResource), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(stringResource(statusResource), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            TextButton(onClick = onClick) { Text(stringResource(R.string.open_feature)) }
        }
    }
}

private data class GuardianFinding(val label: String, val packageName: String, val installer: String, val remoteAccess: Boolean)
private data class DeveloperFlags(val developerOptions: Int, val adb: Int)

@Composable
internal fun GuardianPanel() {
    val context = LocalContext.current
    var refreshKey by remember { mutableStateOf(0) }
    var findings by remember { mutableStateOf<List<GuardianFinding>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var loadFailed by remember { mutableStateOf(false) }
    var developerFlags by remember { mutableStateOf(DeveloperFlags(-1, -1)) }

    LaunchedEffect(context, refreshKey) {
        isLoading = true
        val scanned = withContext(Dispatchers.IO) { runCatching { inspectInstallerSources(context) } }
        findings = scanned.getOrDefault(emptyList())
        loadFailed = scanned.isFailure
        developerFlags = readDeveloperFlags(context)
        isLoading = false
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.guardian_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.guardian_disclaimer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.guardian_developer_settings), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.guardian_developer_state) + ": " + stateLabel(developerFlags.developerOptions), color = if (developerFlags.developerOptions == 1) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurface)
                Text(stringResource(R.string.guardian_adb_state) + ": " + stateLabel(developerFlags.adb), color = if (developerFlags.adb == 1) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurface)
                Text(stringResource(R.string.guardian_settings_limit), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = {
                    runCatching {
                        context.startActivity(Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }.onFailure {
                        runCatching { context.startActivity(Intent(Settings.ACTION_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                        Toast.makeText(context, R.string.guardian_open_settings_failed, Toast.LENGTH_LONG).show()
                    }
                }, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.guardian_review_settings)) }
                OutlinedButton(onClick = { refreshKey++ }, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.guardian_refresh))
                }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(stringResource(R.string.guardian_install_sources), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(stringResource(R.string.guardian_source_explanation), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (isLoading) {
                    CircularProgressIndicator()
                } else if (loadFailed) {
                    Text(stringResource(R.string.guardian_scan_failed), color = MaterialTheme.colorScheme.tertiary)
                } else if (findings.isEmpty()) {
                    Text(stringResource(R.string.guardian_no_findings), color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    findings.take(30).forEach { finding ->
                        Column(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                            Text(finding.label, fontWeight = FontWeight.SemiBold)
                            Text(finding.packageName, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            Text(
                                if (finding.remoteAccess) stringResource(R.string.guardian_remote_tool_notice) else finding.installer,
                                style = MaterialTheme.typography.bodySmall,
                                color = if (finding.remoteAccess) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            TextButton(onClick = {
                                runCatching {
                                    context.startActivity(
                                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + finding.packageName))
                                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    )
                                }.onFailure { Toast.makeText(context, R.string.guardian_open_settings_failed, Toast.LENGTH_LONG).show() }
                            }) { Text(stringResource(R.string.guardian_open_app_info)) }
                        }
                    }
                }
            }
        }
    }
}

private fun stateLabel(flag: Int): String = when (flag) {
    1 -> "Enabled"
    0 -> "Disabled"
    else -> "Unavailable"
}

private fun readDeveloperFlags(context: Context): DeveloperFlags = DeveloperFlags(
    runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, -1) }.getOrDefault(-1),
    runCatching { Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, -1) }.getOrDefault(-1)
)

private fun inspectInstallerSources(context: Context): List<GuardianFinding> {
    val pm = context.packageManager
    return pm.getInstalledApplications(PackageManager.GET_META_DATA)
        .asSequence()
        .filter { it.packageName != context.packageName }
        .map { app ->
            val label = runCatching { app.loadLabel(pm).toString() }.getOrDefault(app.packageName)
            val candidate = (app.packageName + " " + label).lowercase(Locale.ROOT)
            val remote = listOf("anydesk", "teamviewer", "rustdesk").any(candidate::contains)
            val installer = runCatching {
                if (Build.VERSION.SDK_INT >= 30) {
                    val source = pm.getInstallSourceInfo(app.packageName)
                    source.installingPackageName ?: source.initiatingPackageName
                } else null
            }.getOrNull()
            GuardianFinding(
                label = label,
                packageName = app.packageName,
                installer = when {
                    installer == "com.android.vending" -> context.getString(R.string.guardian_source_play)
                    !installer.isNullOrBlank() -> context.getString(R.string.guardian_source_other, installer)
                    else -> context.getString(R.string.guardian_source_unknown)
                },
                remoteAccess = remote
            ) to installer
        }
        .filter { (finding, installer) -> finding.remoteAccess || installer != "com.android.vending" }
        .map { it.first }
        .sortedWith(compareByDescending<GuardianFinding> { it.remoteAccess }.thenBy { it.label.lowercase(Locale.ROOT) })
        .take(60)
        .toList()
}

internal data class UrlAssessment(val suspicious: Boolean, val host: String, val invalid: Boolean)

internal object UrlRiskAssessment {
    private val knownShorteners = setOf("bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy")

    fun assess(input: String): UrlAssessment {
        val raw = input.trim()
        if (raw.isBlank() || raw.length > 4096) return UrlAssessment(false, "", true)
        val candidate = if (raw.contains("://")) raw else "https://" + raw
        val uri = runCatching { URI(candidate) }.getOrNull() ?: return UrlAssessment(false, "", true)
        val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return UrlAssessment(false, "", true)
        if (scheme != "http" && scheme != "https") return UrlAssessment(false, "", true)
        val authority = uri.rawAuthority ?: return UrlAssessment(false, "", true)
        if (authority.isBlank()) return UrlAssessment(false, "", true)
        val hasUserInfo = authority.contains('@')
        val hostPort = authority.substringAfterLast('@')
        val hostRaw = if (hostPort.startsWith("[")) {
            val close = hostPort.indexOf(']')
            if (close <= 1) return UrlAssessment(false, "", true)
            hostPort.substring(1, close)
        } else {
            val portSuffix = hostPort.substringAfterLast(':', "")
            if (portSuffix.isNotBlank() && portSuffix.all(Char::isDigit)) hostPort.substringBeforeLast(':') else hostPort
        }
        val host = runCatching {
            IDN.toASCII(hostRaw, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT).trimEnd('.')
        }.getOrDefault("")
        if (host.isBlank() || host.length > 253 || host.split('.').any { it.isBlank() }) return UrlAssessment(false, "", true)
        val labels = host.split('.')
        val ipLiteral = host.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))
        val nonStandardPort = uri.port > 0 && uri.port != (if (scheme == "https") 443 else 80)
        val suspicious = scheme == "http" || hasUserInfo || ipLiteral || host.length > 70 ||
            labels.any { it.startsWith("xn--") || it.length > 40 } ||
            labels.count { it.contains('-') } >= 4 || knownShorteners.contains(host) || nonStandardPort
        return UrlAssessment(suspicious, host, false)
    }
}

@Composable
internal fun PhishingPanel(
    sharedText: String?,
    repository: ThreatRepository,
    onSharedTextConsumed: () -> Unit
) {
    var input by remember { mutableStateOf(sharedText.orEmpty()) }
    var assessment by remember { mutableStateOf<UrlAssessment?>(null) }
    var feedMatch by remember { mutableStateOf<MalwareHashEntity?>(null) }
    var feedLookupLoading by remember { mutableStateOf(false) }
    var feedLookupComplete by remember { mutableStateOf(false) }
    var feedLookupFailed by remember { mutableStateOf(false) }
    val lookupScope = rememberCoroutineScope()
    var lookupJob by remember { mutableStateOf<Job?>(null) }

    fun resetLookupState() {
        lookupJob?.cancel()
        feedMatch = null
        feedLookupLoading = false
        feedLookupComplete = false
        feedLookupFailed = false
    }

    fun assessAndLookup() {
        val result = UrlRiskAssessment.assess(input)
        assessment = result
        resetLookupState()
        if (result.invalid || result.host.isBlank()) return

        val rawInput = input.trim()
        val normalizedLink = if (rawInput.contains("://")) rawInput else "https://" + rawInput
        val candidates = buildList {
            add(normalizedLink)
            add(result.host)
            if (!rawInput.contains("://")) add("http://" + rawInput)
        }.distinct()
        feedLookupLoading = true
        lookupJob = lookupScope.launch {
            try {
                var matched: MalwareHashEntity? = null
                for (candidate in candidates) {
                    matched = repository.lookupNetworkIoc(candidate)
                    if (matched != null) break
                }
                feedMatch = matched
                feedLookupComplete = true
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                feedLookupFailed = true
            } finally {
                feedLookupLoading = false
            }
        }
    }

    LaunchedEffect(sharedText) {
        if (!sharedText.isNullOrBlank()) {
            input = sharedText.trim()
            assessment = null
            resetLookupState()
            onSharedTextConsumed()
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.phishing_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.phishing_disclaimer), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedTextField(
                    value = input,
                    onValueChange = {
                        input = it
                        assessment = null
                        resetLookupState()
                    },
                    label = { Text(stringResource(R.string.phishing_url_label)) },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
                Button(onClick = { assessAndLookup() }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.Link, contentDescription = null)
                    Text(stringResource(R.string.phishing_assess), modifier = Modifier.padding(start = 8.dp))
                }
                assessment?.let { result ->
                    Text(
                        stringResource(
                            when {
                                result.invalid -> R.string.phishing_invalid
                                result.suspicious -> R.string.phishing_suspicious
                                else -> R.string.phishing_no_local_match
                            }
                        ),
                        fontWeight = FontWeight.Bold,
                        color = when {
                            result.invalid -> MaterialTheme.colorScheme.onSurfaceVariant
                            result.suspicious -> MaterialTheme.colorScheme.tertiary
                            else -> MaterialTheme.colorScheme.primary
                        }
                    )
                    if (result.host.isNotBlank()) {
                        Text(stringResource(R.string.phishing_host) + ": " + result.host, style = MaterialTheme.typography.bodySmall)
                    }
                    if (feedLookupLoading) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                            Text(stringResource(R.string.phishing_feed_checking), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    feedMatch?.let { match ->
                        Text(
                            stringResource(R.string.phishing_feed_match, match.threatName, match.source),
                            style = MaterialTheme.typography.bodyMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.error
                        )
                    } ?: when {
                        feedLookupFailed -> Text(
                            stringResource(R.string.phishing_feed_lookup_error),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.tertiary
                        )
                        feedLookupComplete -> Text(
                            stringResource(R.string.phishing_feed_no_match),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        else -> Unit
                    }
                    Text(stringResource(R.string.phishing_no_feed_notice), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Row(Modifier.padding(14.dp), verticalAlignment = Alignment.Top) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.tertiary, modifier = Modifier.padding(end = 8.dp))
                Text(stringResource(R.string.phishing_limitations), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

private data class StorageCandidate(
    val uri: String,
    val name: String,
    val sizeBytes: Long,
    val lastModified: Long,
    val packageName: String?,
    val apkVersion: Long?,
    val categoryResource: Int,
    val bulkDeleteEligible: Boolean
)

@Composable
internal fun StorageCleanerPanel() {
    val context = LocalContext.current
    val preferences = remember(context) { context.getSharedPreferences("safe_mobile_storage_cleaner", Context.MODE_PRIVATE) }
    var treeUriText by remember { mutableStateOf(preferences.getString("tree_uri", null)) }
    var candidates by remember { mutableStateOf<List<StorageCandidate>>(emptyList()) }
    var selectedUris by remember { mutableStateOf<Set<String>>(emptySet()) }
    var scanning by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var pendingDelete by remember { mutableStateOf<List<StorageCandidate>?>(null) }
    val scope = rememberCoroutineScope()
    val folderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            runCatching {
                context.contentResolver.takePersistableUriPermission(
                    uri,
                    Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                )
            }
            treeUriText = uri.toString()
            preferences.edit().putString("tree_uri", treeUriText).apply()
            candidates = emptyList()
            selectedUris = emptySet()
            message = null
        }
    }
    val eligible = candidates.filter { it.bulkDeleteEligible }
    val selected = candidates.filter { it.uri in selectedUris }
    fun scanSelectedFolder() {
        val uriText = treeUriText
        if (uriText.isNullOrBlank()) {
            folderPicker.launch(null)
            return
        }
        scanning = true
        message = null
        scope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { StorageCleanerEngine.scanTree(context, Uri.parse(uriText)) } }
            result.onSuccess {
                candidates = it
                selectedUris = emptySet()
                message = context.getString(R.string.cleaner_scan_complete, it.size)
            }.onFailure {
                message = context.getString(R.string.cleaner_scan_failed)
            }
            scanning = false
        }
    }
    fun deleteCandidates(requested: List<StorageCandidate>) {
        if (requested.isNotEmpty()) pendingDelete = requested
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.cleaner_title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Text(stringResource(R.string.cleaner_description), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(if (treeUriText.isNullOrBlank()) stringResource(R.string.cleaner_no_folder) else stringResource(R.string.cleaner_folder_selected), style = MaterialTheme.typography.bodyMedium)
                OutlinedButton(onClick = { folderPicker.launch(null) }, modifier = Modifier.fillMaxWidth()) {
                    Icon(Icons.Default.FolderOpen, contentDescription = null)
                    Text(stringResource(R.string.cleaner_choose_folder), modifier = Modifier.padding(start = 8.dp))
                }
                Button(onClick = { scanSelectedFolder() }, enabled = !scanning && !treeUriText.isNullOrBlank(), modifier = Modifier.fillMaxWidth()) {
                    if (scanning) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Text(stringResource(R.string.cleaner_scan_storage), modifier = Modifier.padding(start = 8.dp))
                }
                if (scanning) Text(stringResource(R.string.cleaner_scanning), style = MaterialTheme.typography.bodySmall)
                message?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
        }
        if (candidates.isNotEmpty()) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(stringResource(R.string.cleaner_summary, candidates.size, candidates.sumOf { it.sizeBytes }), fontWeight = FontWeight.SemiBold)
                    candidates.take(100).forEach { item ->
                        Row(verticalAlignment = Alignment.Top, modifier = Modifier.fillMaxWidth()) {
                            Checkbox(
                                checked = item.uri in selectedUris,
                                onCheckedChange = { checked ->
                                    selectedUris = if (checked) selectedUris + item.uri else selectedUris - item.uri
                                }
                            )
                            Column(Modifier.weight(1f).padding(top = 11.dp), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                Text(item.name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                                Text(formatStorageBytes(item.sizeBytes), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                Text(stringResource(item.categoryResource), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary)
                                if (!item.packageName.isNullOrBlank()) {
                                    Text(item.packageName + (item.apkVersion?.let { " · v" + it } ?: ""), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                if (item.bulkDeleteEligible) Text(stringResource(R.string.cleaner_bulk_eligible), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
                            }
                        }
                    }
                    if (candidates.size > 100) Text(stringResource(R.string.cleaner_display_limit), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    OutlinedButton(onClick = { deleteCandidates(selected) }, enabled = selected.isNotEmpty() && !scanning, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.cleaner_delete_selected, selected.size))
                    }
                    Button(onClick = { deleteCandidates(eligible) }, enabled = eligible.isNotEmpty() && !scanning, modifier = Modifier.fillMaxWidth()) {
                        Text(stringResource(R.string.cleaner_delete_all_eligible, eligible.size))
                    }
                    Text(stringResource(R.string.cleaner_bulk_rule), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }

    pendingDelete?.let { deleteSet ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.cleaner_delete_confirm_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(stringResource(R.string.cleaner_delete_confirm_body, deleteSet.size, deleteSet.sumOf { it.sizeBytes }))
                    deleteSet.take(8).forEach { Text("• " + it.name, style = MaterialTheme.typography.bodySmall) }
                    if (deleteSet.size > 8) Text(stringResource(R.string.cleaner_more_files, deleteSet.size - 8), style = MaterialTheme.typography.bodySmall)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    val requested = deleteSet
                    pendingDelete = null
                    scanning = true
                    scope.launch {
                        val result = withContext(Dispatchers.IO) {
                            requested.map { candidate -> candidate to runCatching { StorageCleanerEngine.deleteIfUnchanged(context, candidate) } }
                        }
                        val deleted = result.filter { it.second.getOrDefault(false) }
                        val failed = result.size - deleted.size
                        candidates = candidates.filterNot { current -> deleted.any { it.first.uri == current.uri } }
                        selectedUris = selectedUris - deleted.map { it.first.uri }.toSet()
                        val freed = deleted.sumOf { it.first.sizeBytes }
                        message = context.getString(R.string.cleaner_delete_result, deleted.size, freed, failed)
                        scanning = false
                    }
                }) { Text(stringResource(R.string.cleaner_delete_confirm_action)) }
            },
            dismissButton = { TextButton(onClick = { pendingDelete = null }) { Text(stringResource(R.string.close)) } }
        )
    }
}

private fun formatStorageBytes(bytes: Long): String {
    if (bytes < 0) return "Size unavailable"
    if (bytes < 1024) return bytes.toString() + " B"
    if (bytes < 1024 * 1024) return String.format(Locale.ROOT, "%.1f KB", bytes / 1024.0)
    if (bytes < 1024L * 1024L * 1024L) return String.format(Locale.ROOT, "%.1f MB", bytes / (1024.0 * 1024.0))
    return String.format(Locale.ROOT, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0))
}

private object StorageCleanerEngine {
    private const val MAX_DOCUMENTS = 1500
    private const val MAX_DEPTH = 8
    private const val MAX_APK_BYTES = 256L * 1024L * 1024L
    private const val BULK_MIN_AGE_MS = 30L * 24L * 60L * 60L * 1000L
    private val columns = arrayOf(
        DocumentsContract.Document.COLUMN_DOCUMENT_ID,
        DocumentsContract.Document.COLUMN_DISPLAY_NAME,
        DocumentsContract.Document.COLUMN_SIZE,
        DocumentsContract.Document.COLUMN_MIME_TYPE,
        DocumentsContract.Document.COLUMN_LAST_MODIFIED
    )

    suspend fun scanTree(context: Context, treeUri: Uri): List<StorageCandidate> = withContext(Dispatchers.IO) {
        require(DocumentsContract.isTreeUri(treeUri)) { "Choose a folder using Android's folder picker." }
        val found = mutableListOf<StorageCandidate>()
        val visitedIds = mutableSetOf<String>()
        fun visit(parentId: String, depth: Int) {
            if (depth > MAX_DEPTH || found.size >= MAX_DOCUMENTS || visitedIds.size >= MAX_DOCUMENTS) return
            if (!visitedIds.add(parentId)) return
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, parentId)
            val cursor = context.contentResolver.query(childrenUri, columns, null, null, null) ?: return
            cursor.use { rows ->
                val idIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val sizeIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
                val typeIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val modifiedIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
                while (rows.moveToNext() && found.size < MAX_DOCUMENTS && visitedIds.size < MAX_DOCUMENTS) {
                    if (idIndex < 0 || nameIndex < 0 || typeIndex < 0) break
                    val childId = rows.getString(idIndex) ?: continue
                    val name = rows.getString(nameIndex).orEmpty()
                    val mime = rows.getString(typeIndex).orEmpty()
                    val size = if (sizeIndex >= 0 && !rows.isNull(sizeIndex)) rows.getLong(sizeIndex) else -1L
                    val modified = if (modifiedIndex >= 0 && !rows.isNull(modifiedIndex)) rows.getLong(modifiedIndex) else 0L
                    if (mime == DocumentsContract.Document.MIME_TYPE_DIR) {
                        visit(childId, depth + 1)
                    } else if (name.endsWith(".apk", ignoreCase = true)) {
                        val documentUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, childId)
                        found += inspectApk(context, documentUri, name, size, modified)
                    }
                }
            }
        }
        visit(DocumentsContract.getTreeDocumentId(treeUri), 0)
        found
    }

    private fun inspectApk(context: Context, uri: Uri, name: String, providerSize: Long, modified: Long): StorageCandidate {
        val temp = try {
            File.createTempFile("safemobile-apk-", ".tmp", context.cacheDir)
        } catch (_: Exception) {
            return candidate(uri, name, providerSize, modified, null, null, R.string.cleaner_review_required, false, -1L)
        }
        try {
            val actualSize = context.contentResolver.openInputStream(uri)?.use { input ->
                FileOutputStream(temp).use { output ->
                    val buffer = ByteArray(32 * 1024)
                    var total = 0L
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        total += count
                        if (total > MAX_APK_BYTES) throw IOException("APK exceeds local metadata inspection limit.")
                        output.write(buffer, 0, count)
                    }
                    output.fd.sync()
                    total
                }
            } ?: throw IOException("Content provider could not open the APK.")
            val info = context.packageManager.getPackageArchiveInfo(temp.absolutePath, PackageManager.GET_META_DATA)
                ?: return candidate(uri, name, providerSize, modified, null, null, R.string.cleaner_review_required, false, actualSize)
            val packageName = info.packageName
            val apkVersion = packageVersion(info)
            val installedLookup = installedVersion(context.packageManager, packageName)
            val installedVersion = installedLookup.first
            val definitelyNotInstalled = installedLookup.second
            val category = when {
                definitelyNotInstalled -> R.string.cleaner_orphaned_candidate
                installedVersion == null -> R.string.cleaner_review_required
                apkVersion < installedVersion -> R.string.cleaner_outdated_candidate
                apkVersion == installedVersion -> R.string.cleaner_installed_match
                else -> R.string.cleaner_review_required
            }
            val oldEnough = modified > 0L && System.currentTimeMillis() - modified >= BULK_MIN_AGE_MS
            val eligible = definitelyNotInstalled && oldEnough && packageName.isNotBlank()
            return candidate(uri, name, providerSize, modified, packageName, apkVersion, category, eligible, actualSize)
        } catch (_: Exception) {
            return candidate(uri, name, providerSize, modified, null, null, R.string.cleaner_review_required, false, -1L)
        } finally {
            temp.delete()
        }
    }

    private fun candidate(
        uri: Uri,
        name: String,
        providerSize: Long,
        modified: Long,
        packageName: String?,
        version: Long?,
        category: Int,
        eligible: Boolean,
        actualSize: Long
    ) = StorageCandidate(
        uri = uri.toString(),
        name = name.take(250),
        sizeBytes = if (providerSize >= 0L) providerSize else actualSize,
        lastModified = modified,
        packageName = packageName,
        apkVersion = version,
        categoryResource = category,
        bulkDeleteEligible = eligible
    )

    fun deleteIfUnchanged(context: Context, candidate: StorageCandidate): Boolean {
        val uri = Uri.parse(candidate.uri)
        val snapshot = context.contentResolver.query(uri, columns, null, null, null)?.use { rows ->
            if (!rows.moveToFirst()) null else {
                val nameIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val sizeIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
                val modifiedIndex = rows.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
                if (nameIndex < 0) null else Triple(
                    rows.getString(nameIndex).orEmpty(),
                    if (sizeIndex >= 0 && !rows.isNull(sizeIndex)) rows.getLong(sizeIndex) else -1L,
                    if (modifiedIndex >= 0 && !rows.isNull(modifiedIndex)) rows.getLong(modifiedIndex) else 0L
                )
            }
        } ?: return false
        if (snapshot.first != candidate.name) return false
        if (snapshot.second >= 0L && candidate.sizeBytes >= 0L && snapshot.second != candidate.sizeBytes) return false
        if (snapshot.third > 0L && candidate.lastModified > 0L && snapshot.third != candidate.lastModified) return false
        return DocumentsContract.deleteDocument(context.contentResolver, uri)
    }

    @Suppress("DEPRECATION")
    private fun packageVersion(info: PackageInfo): Long =
        if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()

    @Suppress("DEPRECATION")
    /** Returns (version, definitely-not-installed); access denial is unknown, never orphan proof. */
    private fun installedVersion(pm: PackageManager, packageName: String): Pair<Long?, Boolean> = try {
        val installed = if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            pm.getPackageInfo(packageName, 0)
        }
        packageVersion(installed) to false
    } catch (_: PackageManager.NameNotFoundException) {
        null to true
    } catch (_: SecurityException) {
        null to false
    }
}
