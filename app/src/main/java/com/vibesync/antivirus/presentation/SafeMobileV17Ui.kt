package com.vibesync.antivirus.presentation

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.*
import androidx.core.graphics.drawable.toBitmap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.R
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.data.local.AnalyticsWeek
import com.vibesync.antivirus.data.local.ScanAnalytics
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.core.security.SecurityVerificationState
import com.vibesync.antivirus.core.security.SecurityVerificationStatus
import com.vibesync.antivirus.ui.theme.AppTheme

private data class V17Colors(
    val device: Color, val surface: Color, val elevated: Color, val text: Color,
    val muted: Color, val accent: Color, val green: Color, val amber: Color,
    val red: Color, val border: Color
)

@Composable
@Suppress("UNUSED_PARAMETER")
private fun v17Colors(dark: Boolean): V17Colors {
    val scheme = MaterialTheme.colorScheme
    return V17Colors(
        device = scheme.background,
        surface = scheme.surface,
        elevated = scheme.surfaceVariant,
        text = scheme.onSurface,
        muted = scheme.onSurfaceVariant,
        accent = scheme.primary,
        green = if (scheme.primary == Color(0xFF00E676)) scheme.primary else Color(0xFF10B981),
        amber = scheme.tertiary,
        red = scheme.error,
        border = scheme.outlineVariant
    )
}

@Composable
private fun V17Title(text: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurface) {
    Text(text, modifier, style = MaterialTheme.typography.titleMedium.copy(fontSize = 15.sp, lineHeight = 20.sp),
        fontWeight = FontWeight.SemiBold, color = color, maxLines = 2, overflow = TextOverflow.Ellipsis)
}

@Composable
private fun V17Body(text: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurface) {
    Text(text, modifier, style = MaterialTheme.typography.bodyMedium.copy(fontSize = 13.sp, lineHeight = 19.sp), color = color)
}

@Composable
private fun V17Card(
    dark: Boolean,
    modifier: Modifier = Modifier,
    contentPadding: PaddingValues = PaddingValues(12.dp),
    content: @Composable ColumnScope.() -> Unit
) {
    val c = v17Colors(dark)
    Surface(modifier, color = c.surface, shape = RoundedCornerShape(16.dp), border = BorderStroke(1.dp, c.border)) {
        Column(Modifier.fillMaxWidth().padding(contentPadding), verticalArrangement = Arrangement.spacedBy(8.dp), content = content)
    }
}

@Composable
private fun V17Pill(label: String, color: Color, dark: Boolean) {
    Surface(color = color.copy(alpha = if (dark) .16f else .12f), shape = CircleShape) {
        Text(label.uppercase(), Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp, letterSpacing = 0.5.sp),
            color = color, fontWeight = FontWeight.ExtraBold, maxLines = 1, softWrap = false)
    }
}

@Composable
private fun V17IconBadge(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: Color,
    size: androidx.compose.ui.unit.Dp = 44.dp,
    iconSize: androidx.compose.ui.unit.Dp = 24.dp,
    contentDescription: String? = null,
    modifier: Modifier = Modifier
) {
    Surface(modifier = modifier.size(size), color = tint.copy(alpha = .14f),
        shape = RoundedCornerShape(13.dp), border = BorderStroke(1.dp, tint.copy(alpha = .24f))) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Icon(icon, contentDescription, Modifier.size(iconSize), tint = tint)
        }
    }
}

@Composable
private fun V17SectionHeading(
    title: String, subtitle: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector, tint: Color
) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        V17IconBadge(icon, tint, size = 42.dp, iconSize = 24.dp, contentDescription = title)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            V17Title(title)
            V17Body(subtitle)
        }
    }
}

@Composable
private fun V17HeroCard(dark: Boolean, content: @Composable ColumnScope.() -> Unit) {
    val c = v17Colors(dark)
    Surface(
        color = c.surface,
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, c.border)
    ) {
        Column(
            Modifier.fillMaxWidth()
                .background(Brush.linearGradient(listOf(c.surface, c.elevated)))
                .padding(horizontal = 14.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            content = content
        )
    }
}

@Composable
internal fun V17TopBar(
    appTheme: AppTheme, isPro: Boolean, showBack: Boolean,
    onThemeToggle: () -> Unit, onProClick: () -> Unit, onBack: () -> Unit
) {
    val c = v17Colors(appTheme != AppTheme.LIGHT)
    Surface(color = c.device, border = BorderStroke(0.dp, Color.Transparent)) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            if (showBack) IconButton(onClick = onBack, modifier = Modifier.size(34.dp)) {
                Icon(Icons.Outlined.ArrowBack, "Back", tint = c.text)
            } else Image(
                painter = painterResource(R.drawable.ic_launcher_foreground),
                contentDescription = null,
                modifier = Modifier.size(40.dp)
            )
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(1.dp)) {
                Text(stringResource(R.string.brand_subtitle), style = MaterialTheme.typography.titleMedium.copy(fontSize = 15.sp),
                    fontWeight = FontWeight.Bold, color = c.text)
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.labelSmall.copy(fontSize = 10.sp), color = c.muted)
            }
            IconButton(onClick = onThemeToggle, modifier = Modifier.size(40.dp)) {
                Icon(
                    if (appTheme == AppTheme.LIGHT) Icons.Default.DarkMode else Icons.Default.LightMode,
                    "Toggle theme", tint = c.muted, modifier = Modifier.size(23.dp)
                )
            }
            Surface(Modifier.clip(CircleShape).clickable(role = Role.Button, onClick = onProClick),
                color = if (isPro) c.green else Color(0xFFEA580C), shape = CircleShape) {
                Row(
                    Modifier.padding(horizontal = 10.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Icon(Icons.Outlined.Star, contentDescription = null, modifier = Modifier.size(14.dp), tint = Color.White)
                    Text(if (isPro) "PRO ACTIVE" else "PRO",
                        style = MaterialTheme.typography.labelSmall, color = Color.White, fontWeight = FontWeight.ExtraBold)
                }
            }
        }
    }
}

@Composable
internal fun V17BottomNavigationBar(selectedTab: String, isDark: Boolean, onSelect: (String) -> Unit) {
    val c = v17Colors(isDark)
    val entries = listOf(
        Triple("home", "Shield", Icons.Default.Shield),
        Triple("scan", "Scan & Lab", Icons.Default.Science),
        Triple("tools", "Tools Hub", Icons.Default.Build),
        Triple("settings", "Console", Icons.Default.Tune)
    )
    Surface(color = c.surface, border = BorderStroke(1.dp, c.border)) {
        Row(Modifier.fillMaxWidth().height(72.dp), verticalAlignment = Alignment.CenterVertically) {
            entries.forEach { (route, label, icon) ->
                val selected = route == selectedTab
                Column(
                    Modifier.weight(1f).fillMaxHeight().clip(RoundedCornerShape(12.dp))
                        .clickable(role = Role.Tab, onClick = { onSelect(route) })
                        .testTag("navigation.$route").padding(vertical = 5.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(3.dp)
                ) {
                    Surface(
                        color = if (selected) c.accent.copy(alpha = .16f) else Color.Transparent,
                        shape = RoundedCornerShape(14.dp),
                        border = if (selected) BorderStroke(1.dp, c.accent.copy(alpha = .28f)) else null
                    ) {
                        Icon(icon, "$label tab",
                            Modifier.padding(horizontal = 17.dp, vertical = 4.dp).size(24.dp),
                            tint = if (selected) c.accent else c.muted)
                    }
                    Text(label, style = MaterialTheme.typography.labelSmall.copy(fontSize = 11.sp),
                        fontWeight = FontWeight.SemiBold, color = if (selected) c.accent else c.muted,
                        maxLines = 1, softWrap = false)
                }
            }
        }
    }
}

@Composable
internal fun V17ShieldScreen(
    isDark: Boolean, securityScore: Int, isPro: Boolean, activeGuards: Int,
    integrityState: SecurityVerificationState,
    liveSentinelActive: Boolean, posturePassed: Int?, quarantinedFilesCount: Int,
    onOpenSetup: () -> Unit, onOpenLiveSentinel: () -> Unit, onOpenPosture: () -> Unit,
    onOpenDetection: () -> Unit, onOpenThreatDb: () -> Unit,
    onOpenPrivacy: () -> Unit = {}, onOpenSettings: () -> Unit = {}
) {
    val c = v17Colors(isDark)
    Column(Modifier.fillMaxSize().background(c.device).verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        V17HeroCard(isDark) {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                V17ScoreRing(securityScore.coerceIn(0, 100), isDark)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    V17IconBadge(Icons.Default.Shield, c.green, size = 36.dp, iconSize = 21.dp, contentDescription = null)
                    V17Pill(if (isPro) "PRO · AD-FREE" else "PROTECTION STATUS", c.green, isDark)
                }
                V17Title(stringResource(R.string.ui_score_title))
                V17Body(stringResource(R.string.v116_score_meaning))
                V17Body(stringResource(R.string.ui_score_explanation))
                V17Body("$activeGuards/3 protection guards active")
            }
        }
        TrustPillarCarousel(
            onOpenPrivacy = onOpenPrivacy,
            onOpenSettings = onOpenSettings
        )
        V17Card(isDark) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(
                    imageVector = if (integrityState.meetsDeviceIntegrity == true)
                        Icons.Outlined.CheckCircle else Icons.Outlined.Security,
                    contentDescription = null,
                    tint = if (integrityState.meetsDeviceIntegrity == true) c.green else c.muted,
                    modifier = Modifier.size(26.dp)
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    V17Title(stringResource(R.string.play_integrity_verified_title))
                    V17Body(stringResource(when (integrityState.status) {
                        SecurityVerificationStatus.VERIFIED -> R.string.play_integrity_status_verified
                        SecurityVerificationStatus.NOT_VERIFIED -> R.string.play_integrity_status_not_verified
                        SecurityVerificationStatus.REQUESTING_TOKEN -> R.string.play_integrity_status_requesting
                        SecurityVerificationStatus.AWAITING_SERVER_VERDICT -> R.string.play_integrity_status_server_unconfigured
                        SecurityVerificationStatus.ERROR -> R.string.play_integrity_status_error
                        SecurityVerificationStatus.NOT_CHECKED -> R.string.play_integrity_status_not_checked
                    }), color = c.muted)
                }
            }
        }
        if (activeGuards < 3) Surface(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).clickable(onClick = onOpenSetup),
            color = c.amber.copy(alpha = .14f), shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, c.amber.copy(alpha = .4f))
        ) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                V17IconBadge(Icons.Outlined.Tune, c.amber, size = 40.dp, iconSize = 22.dp, contentDescription = null)
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    V17Title("Protection Setup: $activeGuards/3 Active", color = c.text)
                    V17Body("Tap to grant the remaining recommended protection permissions.", color = c.muted)
                }
                V17Pill("FINISH", c.amber, isDark)
                Icon(Icons.Default.ArrowForward, contentDescription = null, tint = c.amber, modifier = Modifier.size(18.dp))
            }
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            V17Tile("Live Sentinel", "Install & download observer", if (liveSentinelActive) "ACTIVE" else "INACTIVE",
                Icons.Default.Security, c.green, isDark, Modifier.weight(1f), onOpenLiveSentinel)
            V17Tile("Device Posture", "Bootloader, SELinux, ADB & Play Protect",
                posturePassed?.let { "$it/8 PASSED" } ?: "CHECK", Icons.Default.Smartphone,
                c.accent, isDark, Modifier.weight(1f), onOpenPosture)
        }
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            V17Tile("AI & YARA Engine", "Four-layer ensemble analysis", "4-LAYER",
                Icons.Default.Psychology, c.accent, isDark, Modifier.weight(1f), onOpenDetection)
            V17Tile("Threat DB & Vault", "Local threat data and isolation",
                if (quarantinedFilesCount > 0) "$quarantinedFilesCount ISOLATED" else "READY",
                Icons.Default.Lock, c.amber, isDark, Modifier.weight(1f), onOpenThreatDb)
        }
    }
}

private const val SCORE_GAUGE_ANIMATION_LABEL = "security-score-gauge"
private const val SCORE_VALUE_ANIMATION_LABEL = "security-score-value"

@Composable
private fun V17ScoreRing(score: Int, isDark: Boolean) {
    val c = v17Colors(isDark)
    val targetScore = score.coerceIn(0, 100)
    val progress by animateFloatAsState(
        targetValue = targetScore / 100f,
        animationSpec = tween(500),
        label = SCORE_GAUGE_ANIMATION_LABEL
    )
    val displayedScore by androidx.compose.animation.core.animateIntAsState(
        targetValue = targetScore,
        animationSpec = tween(500),
        label = SCORE_VALUE_ANIMATION_LABEL
    )
    Box(Modifier.size(216.dp), contentAlignment = Alignment.Center) {
        Canvas(Modifier.fillMaxSize()) {
            val strokeWidth = 18.dp.toPx()
            val arcSize = androidx.compose.ui.geometry.Size(size.width - strokeWidth, size.height - strokeWidth)
            val topLeft = androidx.compose.ui.geometry.Offset(strokeWidth / 2, strokeWidth / 2)
            drawArc(
                color = c.border.copy(alpha = 0.55f),
                startAngle = -90f,
                sweepAngle = 360f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(strokeWidth, cap = StrokeCap.Round)
            )
            val rainbow = Brush.sweepGradient(
                colors = listOf(
                    Color(0xFFEF4444),
                    Color(0xFFF97316),
                    Color(0xFFFACC15),
                    Color(0xFF84CC16),
                    Color(0xFF22C55E),
                    Color(0xFFEF4444)
                ),
                center = center
            )
            drawArc(
                brush = rainbow,
                startAngle = -90f,
                sweepAngle = progress * 360f,
                useCenter = false,
                topLeft = topLeft,
                size = arcSize,
                style = Stroke(strokeWidth, cap = StrokeCap.Round)
            )
        }
        Column(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 26.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(3.dp)
        ) {
            Text(
                displayedScore.toString(),
                style = MaterialTheme.typography.displayLarge.copy(fontSize = 54.sp, lineHeight = 60.sp),
                fontWeight = FontWeight.ExtraBold,
                color = c.text,
                maxLines = 1
            )
            Text(
                stringResource(R.string.ui_score_title),
                Modifier.fillMaxWidth(),
                style = MaterialTheme.typography.labelMedium,
                color = c.muted,
                textAlign = TextAlign.Center,
                maxLines = 2,
                softWrap = true,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun V17Tile(
    title: String, subtitle: String, status: String, icon: androidx.compose.ui.graphics.vector.ImageVector,
    tint: Color, dark: Boolean, modifier: Modifier, onClick: () -> Unit
) {
    V17Card(dark, modifier.heightIn(min = 126.dp).clip(RoundedCornerShape(16.dp))
        .clickable(role = Role.Button, onClick = onClick)) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            V17IconBadge(icon, tint, size = 42.dp, iconSize = 25.dp, contentDescription = title)
            Spacer(Modifier.weight(1f))
            V17Pill(status, tint, dark)
        }
        Spacer(Modifier.height(2.dp))
        V17Title(title)
        V17Body(subtitle)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun V17ProtectionSetupSheet(
    isDark: Boolean, batteryActive: Boolean, safActive: Boolean,
    onDismiss: () -> Unit, onBatteryToggle: (Boolean) -> Unit,
    onSafToggle: (Boolean) -> Unit
) {
    val c = v17Colors(isDark)
    ModalBottomSheet(onDismissRequest = onDismiss, containerColor = c.surface,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            V17Title(stringResource(R.string.setup_checklist_title))
            V17Body(stringResource(R.string.setup_checklist_body))
            listOf(
                Triple(stringResource(R.string.setup_checklist_battery), batteryActive, onBatteryToggle),
                Triple(stringResource(R.string.setup_checklist_saf), safActive, onSafToggle)
            ).forEachIndexed { index, (title, checked, onToggle) ->
                val icon = when (index) {
                    0 -> Icons.Outlined.BatteryChargingFull
                    1 -> Icons.Outlined.Security
                    else -> Icons.Outlined.Storage
                }
                Surface(
                    Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                        .clickable(onClick = { onToggle(!checked) }),
                    color = c.elevated,
                    shape = RoundedCornerShape(12.dp)
                ) {
                    Row(Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        V17IconBadge(icon, c.accent, size = 34.dp, iconSize = 19.dp, contentDescription = title)
                        V17Title(title, Modifier.weight(1f))
                        Checkbox(checked = checked, onCheckedChange = onToggle)
                    }
                }
            }
            Button(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.close))
            }
            Spacer(Modifier.height(16.dp))
        }
    }
}

@Composable
internal fun V17ScanLabScreen(
    isDark: Boolean, state: SafeMobileUiState, repository: ThreatRepository? = null,
    onStartQuickScan: () -> Unit, onStartDeepScan: () -> Unit,
    onCancelScan: () -> Unit, onUninstall: (String) -> Unit, onAppInfo: (String) -> Unit,
    onQuarantine: (ScanResult) -> Unit, onTrust: (ScanResult) -> Unit, onRemoveTrust: (String) -> Unit
) {
    val c = v17Colors(isDark)
    var deep by rememberSaveable { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().background(c.device).verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        V17Card(isDark) {
            V17SectionHeading("Run Smart Scan",
                "Progressive four-layer inspection using the on-device scan pipeline.",
                Icons.Outlined.Science, c.accent)
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).background(c.elevated).padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                V17ModeButton("Quick App Scan", Icons.Outlined.Apps, !deep, isDark, Modifier.weight(1f)) { deep = false }
                V17ModeButton("Deep Storage (Worker)", Icons.Outlined.FolderOpen, deep, isDark, Modifier.weight(1f)) { deep = true }
            }
            Button(onClick = { if (deep) onStartDeepScan() else onStartQuickScan() },
                enabled = !state.isScanning, modifier = Modifier.fillMaxWidth()) {
                if (state.isScanning) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.scan_running))
                } else {
                    Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(21.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(if (deep) R.string.cleaner_scan_storage else R.string.scan_installed))
                }
            }
            if (state.isScanning) {
                if (state.totalItems > 0) LinearProgressIndicator(
                    progress = { (state.processedItems.toFloat() / state.totalItems).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth()
                ) else LinearProgressIndicator(Modifier.fillMaxWidth())
                V17Body(if (state.totalItems > 0) "Scanning ${state.processedItems} of ${state.totalItems}"
                    else stringResource(R.string.scan_running))
                TextButton(onClick = onCancelScan) { Text(stringResource(R.string.scan_cancel)) }
            }
        }
        V17Card(isDark) {
            V17SectionHeading("Scan Results", "Tap a result to inspect the four detection layers.",
                Icons.Outlined.Assessment, c.amber)
            if (state.results.isEmpty()) {
                Row(Modifier.fillMaxWidth().padding(vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    V17IconBadge(Icons.Outlined.Search, c.muted, size = 44.dp, iconSize = 25.dp,
                        contentDescription = null)
                    V17Body("No scan results yet. Run Quick App Scan or choose a folder for deep scanning.")
                }
            }
            state.results.take(80).forEach { result ->
                V17ScanResultRow(result, isDark, onUninstall, onAppInfo,
                    { onQuarantine(result) }, { onTrust(result) }, { result.packageName?.let(onRemoveTrust) })
            }
        }
        V17Card(isDark) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                V17IconBadge(Icons.Outlined.Assessment, c.accent, size = 40.dp, iconSize = 22.dp,
                    contentDescription = stringResource(R.string.scan_lab_metrics_title))
                Column(Modifier.weight(1f)) {
                    V17Title(stringResource(R.string.scan_lab_metrics_title))
                    V17Body(stringResource(R.string.scan_lab_metrics_body))
                }
            }
            HorizontalDivider(color = c.border)
            BenchmarkResultsPanel()
            if (repository != null) AnalyticsCharts(repository, state.results)
            else AnalyticsChartContent(ScanAnalytics(), AnalyticsWeek.current(), state.results)
        }
    }
}

@Composable
private fun V17ModeButton(
    label: String, icon: androidx.compose.ui.graphics.vector.ImageVector,
    selected: Boolean, dark: Boolean, modifier: Modifier, onClick: () -> Unit
) {
    val c = v17Colors(dark)
    Surface(
        modifier.clip(RoundedCornerShape(9.dp)).clickable(role = Role.Button, onClick = onClick),
        color = if (selected) c.surface else Color.Transparent, shape = RoundedCornerShape(9.dp),
        border = if (selected) BorderStroke(1.dp, c.border) else null
    ) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 7.dp, vertical = 9.dp),
            horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, modifier = Modifier.size(17.dp), tint = if (selected) c.accent else c.muted)
            Spacer(Modifier.width(5.dp))
            Text(label, style = MaterialTheme.typography.labelMedium.copy(fontSize = 11.sp),
                color = if (selected) c.text else c.muted, fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center, maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun V17ScanResultRow(
    result: ScanResult, dark: Boolean, onUninstall: (String) -> Unit, onAppInfo: (String) -> Unit,
    onQuarantine: () -> Unit, onTrust: () -> Unit, onRemoveTrust: () -> Unit
) {
    val context = LocalContext.current
    val c = v17Colors(dark)
    var expanded by rememberSaveable(result.packageName, result.packageOrPath) { mutableStateOf(false) }
    var heuristicsExpanded by rememberSaveable(result.packageName, result.packageOrPath) { mutableStateOf(false) }
    val appIcon = remember(context, result.packageName) {
        result.packageName?.let { name ->
            runCatching {
                context.packageManager.getApplicationIcon(name).toBitmap(72, 72).asImageBitmap()
            }.getOrNull()
        }
    }
    val uninstallAllowed = result.packageName?.let { name ->
        name != context.packageName &&
            result.verdict in setOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS) &&
            !result.trustedByUser &&
            runCatching {
                SystemPackageGuard.evaluate(context, name) is PackageGuardResult.Allowed
            }.getOrDefault(false)
    } == true
    val (label, tint) = when {
        result.trustedByUser -> "WHITELISTED" to c.green
        result.verdict == ScanVerdict.THREAT -> "MALWARE" to c.red
        result.verdict == ScanVerdict.SUSPICIOUS -> "SUSPICIOUS" to c.amber
        result.verdict == ScanVerdict.NO_MATCH -> "CLEAN" to c.green
        else -> "NOT SCANNED" to c.muted
    }
    val verdictIcon = when {
        result.trustedByUser -> Icons.Default.Shield
        result.verdict == ScanVerdict.THREAT -> Icons.Default.Warning
        result.verdict == ScanVerdict.SUSPICIOUS -> Icons.Default.Search
        result.verdict == ScanVerdict.NO_MATCH -> Icons.Default.CheckCircle
        else -> Icons.Outlined.HelpOutline
    }
    Column(Modifier.fillMaxWidth().animateContentSize().clip(RoundedCornerShape(12.dp))
        .background(c.elevated).clickable { expanded = !expanded }.padding(10.dp),
        verticalArrangement = Arrangement.spacedBy(9.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Surface(Modifier.size(42.dp), shape = RoundedCornerShape(11.dp), color = c.surface,
                border = BorderStroke(1.dp, c.border)) {
                if (appIcon != null) Image(appIcon, contentDescription = result.displayName, modifier = Modifier.fillMaxSize())
                else Box(contentAlignment = Alignment.Center) {
                    Icon(Icons.Outlined.Apps, "App icon", tint = c.accent, modifier = Modifier.size(26.dp))
                }
            }
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                V17Title(result.displayName)
                V17Body(result.packageName ?: result.packageOrPath, color = c.muted)
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Icon(verdictIcon, "$label scan result", modifier = Modifier.size(18.dp), tint = tint)
                V17Pill(label, tint, dark)
            }
        }
        AnimatedVisibility(expanded) {
            Column(Modifier.fillMaxWidth().padding(top = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                val report = result.riskReport
                V17Body(
                    "ThreatEnsembleEvaluator · ${result.detectionSource}" +
                        if (result.confidence > 0f) " · ${(result.confidence * 100).toInt().coerceIn(0, 100)}% confidence" else
                            " · Risk ${report?.riskScore ?: result.riskScore.toInt()}/100",
                    color = c.text
                )
                val hashDetails = if (result.detectionSource in setOf(
                    DetectionSource.HASH, DetectionSource.SIGNED_DATABASE, DetectionSource.THREAT_INTELLIGENCE_FEED
                )) "Exact digest match: ${result.detectionSource}" else "No exact hash match recorded."
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        V17Layer("1. SHA-256 Hash", hashDetails, c, Modifier.weight(1f), Icons.Outlined.Storage)
                        V17Layer("2. YARA Rules", report?.yaraResult?.matchedRules?.take(8)?.joinToString()
                            ?.takeUnless { it.isBlank() } ?: "No matching YARA rule recorded.", c, Modifier.weight(1f), Icons.Outlined.Science)
                    }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        V17Layer("3. ML Behavioral Model", result.mlProbability?.let {
                            "Model probability: ${(it * 100).toInt().coerceIn(0, 100)}%"
                        } ?: "Model output unavailable for this scan.", c, Modifier.weight(1f), Icons.Outlined.Security)
                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            val heuristicDetails = buildList {
                                report?.findings?.forEach { add("${it.ruleId}: ${it.evidence}") }
                                report?.observations?.forEach { add(it) }
                            }
                            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Outlined.Settings, contentDescription = null,
                                    modifier = Modifier.size(18.dp), tint = c.accent)
                                Spacer(Modifier.width(4.dp))
                                V17Body(if (heuristicDetails.isEmpty()) "4. Static / DEX Heuristics · No findings"
                                    else "4. Static / DEX Heuristics · ${heuristicDetails.size} signals", Modifier.weight(1f), c.text)
                                if (heuristicDetails.isNotEmpty()) TextButton(onClick = { heuristicsExpanded = !heuristicsExpanded }) {
                                    Text(if (heuristicsExpanded) "Hide" else "Show")
                                }
                            }
                            AnimatedVisibility(visible = heuristicsExpanded && heuristicDetails.isNotEmpty()) {
                                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    heuristicDetails.take(12).forEach { V17Body(it, color = c.muted) }
                                }
                            }
                        }
                    }
                }
                if (result.malwareName != null) V17Body("Matched signature: ${result.malwareName}", color = c.text)
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (uninstallAllowed) OutlinedButton(onClick = { result.packageName?.let(onUninstall) },
                        Modifier.weight(1f), contentPadding = PaddingValues(4.dp)) { Text(stringResource(R.string.uninstall_app), maxLines = 1) }
                    if (result.sourceUri != null && result.verdict in setOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS) && !result.trustedByUser) OutlinedButton(onClick = onQuarantine,
                        Modifier.weight(1f), contentPadding = PaddingValues(4.dp)) { Text(stringResource(R.string.quarantine_confirm_action), maxLines = 1) }
                    if (result.packageName != null && !result.trustedByUser) OutlinedButton(onClick = onTrust,
                        Modifier.weight(1f), contentPadding = PaddingValues(4.dp)) { Text(stringResource(R.string.trusted_app_mark), maxLines = 1) }
                }
                if (result.packageName != null) TextButton(onClick = { onAppInfo(result.packageName) }) { Text(stringResource(R.string.guardian_open_app_info)) }
            }
        }
    }
}

@Composable
private fun V17Layer(
    title: String,
    detail: String,
    c: V17Colors,
    modifier: Modifier = Modifier,
    icon: androidx.compose.ui.graphics.vector.ImageVector? = null
) {
    Column(modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(c.surface).padding(8.dp),
        verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(5.dp)) {
            if (icon != null) Icon(icon, null, Modifier.size(17.dp), tint = c.accent)
            V17Title(title, Modifier.weight(1f), color = c.text)
        }
        V17Body(detail, color = c.muted)
    }
}

@Composable
internal fun V17ToolsHubScreen(isDark: Boolean, onOpen: (String) -> Unit) {
    val c = v17Colors(isDark)
    data class Tool(val name: String, val subtitle: String, val icon: androidx.compose.ui.graphics.vector.ImageVector,
                    val route: String, val tint: Color)
    val tools = listOf(
        Tool("Device Posture", "8-point OS & hardware audit", Icons.Default.Shield, "posture", c.accent),
        Tool("Link Checker", "Phishing and URL risk scanner", Icons.Default.Link, "phishing", c.green),
        Tool("Quarantine Vault", "Isolate and purge suspicious files", Icons.Default.Lock, "quarantine", c.amber),
        Tool("Folder Monitor", "SAF directory watch", Icons.Default.Folder, "sentinel", c.accent),
        Tool("System App Guard", "Pre-installed package integrity", Icons.Default.Settings, "guardian", c.green),
        Tool("Security Advisor", "Step-by-step hardening guide", Icons.Default.Lightbulb, "advisor", c.accent)
    )
    Column(Modifier.fillMaxSize().background(c.device).padding(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        V17SectionHeading("Tools Hub", "Security controls and investigation tools.", Icons.Default.Build, c.accent)
        LazyVerticalGrid(GridCells.Fixed(2), Modifier.weight(1f).fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(16.dp), verticalArrangement = Arrangement.spacedBy(16.dp),
            contentPadding = PaddingValues(bottom = 16.dp)) {
            items(tools) { tool ->
                V17Card(isDark, Modifier.heightIn(min = 140.dp).clip(RoundedCornerShape(16.dp))
                    .clickable(role = Role.Button, onClick = { onOpen(tool.route) })) {
                    V17IconBadge(tool.icon, tool.tint, size = 46.dp, iconSize = 27.dp, contentDescription = tool.name)
                    V17Title(tool.name)
                    V17Body(tool.subtitle, color = c.muted)
                    Icon(Icons.Outlined.ChevronRight, null, Modifier.align(Alignment.End).size(20.dp), tint = c.muted)
                }
            }
        }
    }
}

@Composable
internal fun V17ConsoleSettingsScreen(
    isDark: Boolean, appTheme: AppTheme, onAppThemeChanged: (AppTheme) -> Unit,
    sirenEnabled: Boolean, onSirenChanged: (Boolean) -> Unit, voiceEnabled: Boolean,
    onVoiceChanged: (Boolean) -> Unit, installSentinelEnabled: Boolean, installSentinelRunning: Boolean,
    onInstallSentinelChanged: (Boolean) -> Unit, globalIntelEnabled: Boolean,
    onGlobalIntelChanged: (Boolean) -> Unit,
    batteryActive: Boolean, safActive: Boolean,
    integrityState: SecurityVerificationState,
    onBatteryToggle: (Boolean) -> Unit,
    onSafToggle: (Boolean) -> Unit,
    onImportYara: () -> Unit,
    onThreatFeedSync: () -> Unit, onBenchmarks: () -> Unit, onOpenPro: () -> Unit,
    onOpenPrivacy: () -> Unit = {}, onOpenAbout: () -> Unit = {},
    onTestSiren: () -> Unit = {}, onTestVoice: () -> Unit = {}
) {
    val context = LocalContext.current
    val c = v17Colors(isDark)
    var advanced by rememberSaveable { mutableStateOf(false) }
    var languageOpen by rememberSaveable { mutableStateOf(false) }
    var selectedLanguage by rememberSaveable { mutableStateOf(LocalePreferences.overrideTag(context)) }
    Column(Modifier.fillMaxSize().background(c.device).verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        V17Card(isDark) {
            V17SectionHeading("Appearance", "Theme and language preferences.", Icons.Outlined.Palette, c.accent)
            V17Title("Theme")
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(AppTheme.LIGHT, AppTheme.DARK_SLATE, AppTheme.OLED).forEach { theme ->
                    FilterChip(selected = appTheme == theme, onClick = { onAppThemeChanged(theme) },
                        modifier = Modifier.weight(1f), label = { Text(stringResource(when (theme) {
                            AppTheme.LIGHT -> R.string.theme_light
                            AppTheme.DARK_SLATE -> R.string.theme_dark_slate
                            AppTheme.MIDNIGHT -> R.string.theme_dark_slate
                            AppTheme.OLED -> R.string.theme_oled
                        }), style = MaterialTheme.typography.labelMedium.copy(fontSize = 11.sp)) })
                }
            }
            HorizontalDivider(color = c.border)
            Row(Modifier.fillMaxWidth().clickable { languageOpen = true }.padding(vertical = 5.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.Language, null, tint = c.muted)
                Column(Modifier.weight(1f).padding(start = 10.dp)) {
                    V17Title("App Language")
                    V17Body(LocalePreferences.choices.firstOrNull { it.tag == selectedLanguage }
                        ?.let { context.getString(it.labelResource) } ?: "System default", color = c.muted)
                }
                Icon(Icons.Outlined.ChevronRight, "Choose language", tint = c.muted)
            }
        }
        V17Card(isDark) {
            V17SectionHeading(stringResource(R.string.trust_pillars_heading),
                stringResource(R.string.privacy_dashboard_intro), Icons.Outlined.Security, c.accent)
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable(onClick = onOpenPrivacy).padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                V17IconBadge(Icons.Outlined.Lock, c.green, size = 38.dp, iconSize = 21.dp, contentDescription = null)
                Column(Modifier.weight(1f)) {
                    V17Title(stringResource(R.string.privacy_dashboard_title))
                    V17Body(stringResource(R.string.settings_privacy_link_detail), color = c.muted)
                }
                Icon(Icons.Outlined.ChevronRight, contentDescription = null, tint = c.muted)
            }
            HorizontalDivider(color = c.border)
            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable(onClick = onOpenAbout).padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                V17IconBadge(Icons.Outlined.Info, c.accent, size = 38.dp, iconSize = 21.dp, contentDescription = null)
                Column(Modifier.weight(1f)) {
                    V17Title(stringResource(R.string.about_us_title))
                    V17Body(stringResource(R.string.settings_about_link_detail), color = c.muted)
                }
                Icon(Icons.Outlined.ChevronRight, contentDescription = null, tint = c.muted)
            }
        }
        V17Card(isDark) {
            V17SectionHeading("Active Defense", "Local alarms and on-device monitoring.", Icons.Outlined.Security, c.green)
            V17Switch("Incident Siren", "Local incident alarm and notifications", sirenEnabled, "console.siren", Icons.Outlined.Notifications, isDark, onSirenChanged)
            HorizontalDivider(color = c.border)
            V17Switch("Voice Threat Alert", "Offline text-to-speech threat narration", voiceEnabled, "console.voice", Icons.Outlined.VolumeUp, isDark, onVoiceChanged)
            HorizontalDivider(color = c.border)
            V17Switch("Install Sentinel", if (installSentinelRunning) "Observer is running" else "Automatically inspect newly installed apps",
                installSentinelEnabled, "console.install-sentinel", Icons.Outlined.Security, isDark, onInstallSentinelChanged)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onTestSiren, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Outlined.Notifications, null, modifier = Modifier.size(17.dp))
                    Spacer(Modifier.width(5.dp))
                    Text(stringResource(R.string.test_siren), maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
                OutlinedButton(onClick = onTestVoice, modifier = Modifier.weight(1f)) {
                    Icon(Icons.Outlined.VolumeUp, null, modifier = Modifier.size(17.dp))
                    Spacer(Modifier.width(5.dp))
                    Text(stringResource(R.string.test_voice), maxLines = 2, overflow = TextOverflow.Ellipsis)
                }
            }
        }
        V17Card(isDark) {
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Icon(
                    imageVector = if (integrityState.meetsDeviceIntegrity == true)
                        Icons.Outlined.CheckCircle else Icons.Outlined.Security,
                    contentDescription = null,
                    tint = if (integrityState.meetsDeviceIntegrity == true) c.green else c.muted,
                    modifier = Modifier.size(26.dp)
                )
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(3.dp)) {
                    V17Title(stringResource(R.string.play_integrity_verified_title))
                    V17Body(stringResource(when (integrityState.status) {
                        SecurityVerificationStatus.VERIFIED -> R.string.play_integrity_status_verified
                        SecurityVerificationStatus.NOT_VERIFIED -> R.string.play_integrity_status_not_verified
                        SecurityVerificationStatus.REQUESTING_TOKEN -> R.string.play_integrity_status_requesting
                        SecurityVerificationStatus.AWAITING_SERVER_VERDICT -> R.string.play_integrity_status_server_unconfigured
                        SecurityVerificationStatus.ERROR -> R.string.play_integrity_status_error
                        SecurityVerificationStatus.NOT_CHECKED -> R.string.play_integrity_status_not_checked
                    }), color = c.muted)
                }
            }
        }
        V17Card(isDark) {
            V17SectionHeading(stringResource(R.string.security_guards_title),
                stringResource(R.string.security_guards_description), Icons.Outlined.Tune, c.accent)
            V17Switch(stringResource(R.string.security_guard_battery),
                stringResource(R.string.security_guard_battery_desc), batteryActive, "console.guard.battery",
                Icons.Outlined.BatteryChargingFull, isDark, onBatteryToggle)
            HorizontalDivider(color = c.border)
            V17Switch(stringResource(R.string.security_guard_saf),
                stringResource(R.string.security_guard_saf_desc), safActive, "console.guard.saf",
                Icons.Outlined.Storage, isDark, onSafToggle)
        }
        V17Card(isDark) {
            Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                .clickable(role = Role.Button) { advanced = !advanced },
                verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                V17IconBadge(Icons.Outlined.Settings, c.accent, size = 40.dp, iconSize = 23.dp,
                    contentDescription = null)
                Column(Modifier.weight(1f)) {
                    V17Title("Advanced Telemetry & Rules")
                    V17Body("YARA imports, ThreatFeed sync, global intelligence and benchmarks.")
                }
                Icon(if (advanced) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    if (advanced) "Collapse" else "Expand", tint = c.muted, modifier = Modifier.size(22.dp))
            }
            AnimatedVisibility(advanced) {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    HorizontalDivider(color = c.border)
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) { V17Title("YARA custom rules"); V17Body("Import a local .yar rule.") }
                        OutlinedButton(onClick = onImportYara, modifier = Modifier.weight(1f)) {
                            Icon(Icons.Outlined.FolderOpen, null, modifier = Modifier.size(17.dp))
                            Spacer(Modifier.width(5.dp))
                            Text(stringResource(R.string.detection_capabilities_import_yara), maxLines = 2, overflow = TextOverflow.Ellipsis)
                        }
                    }
                    HorizontalDivider(color = c.border)
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) { V17Title("ThreatFeed Sync"); V17Body("Run the configured feed sync.") }
                        OutlinedButton(onClick = onThreatFeedSync) {
                            Icon(Icons.Outlined.Refresh, null, modifier = Modifier.size(17.dp))
                            Spacer(Modifier.width(5.dp))
                            Text(stringResource(R.string.threat_feed_sync_now))
                        }
                    }
                    HorizontalDivider(color = c.border)
                    V17Switch("Global Threat Intelligence", "Opt in to explicitly approved hash contributions",
                        globalIntelEnabled, "console.global-intel", Icons.Outlined.Security, isDark, onGlobalIntelChanged)
                    HorizontalDivider(color = c.border)
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) { V17Title("Benchmarks & Analytics"); V17Body("Review local scan timing and results.") }
                        OutlinedButton(onClick = onBenchmarks) {
                            Icon(Icons.Outlined.Assessment, null, modifier = Modifier.size(17.dp))
                            Spacer(Modifier.width(5.dp))
                            Text(stringResource(R.string.open_feature))
                        }
                    }
                }
            }
        }
        OutlinedButton(onClick = onOpenPro, Modifier.fillMaxWidth()) {
            Icon(Icons.Outlined.Star, null, modifier = Modifier.size(18.dp))
            Spacer(Modifier.width(7.dp))
            Text(stringResource(R.string.pro_title))
        }
        Text(BuildConfig.VERSION_NAME, Modifier.align(Alignment.CenterHorizontally),
            style = MaterialTheme.typography.labelSmall, color = c.muted)
    }
    if (languageOpen) AlertDialog(onDismissRequest = { languageOpen = false },
        title = { V17Title("App Language") },
        text = {
            Column(Modifier.fillMaxWidth().heightIn(max = 420.dp).verticalScroll(rememberScrollState())) {
                TextButton(onClick = { selectedLanguage = ""; LocalePreferences.saveOverride(context, ""); languageOpen = false }) {
                    Text(stringResource(R.string.language_system_default))
                }
                LocalePreferences.choices.forEach { choice ->
                    TextButton(onClick = {
                        selectedLanguage = choice.tag
                        LocalePreferences.saveOverride(context, choice.tag)
                        languageOpen = false
                        (context as? android.app.Activity)?.recreate()
                    }, modifier = Modifier.fillMaxWidth()) { Text(context.getString(choice.labelResource)) }
                }
            }
        }, confirmButton = { TextButton(onClick = { languageOpen = false }) { Text(stringResource(R.string.close)) } })
}

@Composable
private fun V17Switch(
    title: String, subtitle: String, checked: Boolean, tag: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector, dark: Boolean, onChange: (Boolean) -> Unit
) {
    val c = v17Colors(dark)
    Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        V17IconBadge(icon, c.accent, size = 36.dp, iconSize = 20.dp, contentDescription = title)
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            V17Title(title)
            V17Body(subtitle, color = c.muted)
        }
        Switch(checked = checked, onCheckedChange = onChange, modifier = Modifier.testTag(tag))
    }
}
