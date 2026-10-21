package com.vibesync.antivirus.presentation
import android.app.Activity
import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings as SettingsIcon
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import android.widget.Toast
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.ads.BannerAd
import com.vibesync.antivirus.ads.ConsentManager
import com.vibesync.antivirus.ads.InterstitialAdController
import com.vibesync.antivirus.core.connectivity.ConnectivityMonitor
import com.vibesync.antivirus.core.worker.OverlayRiskReviewManager
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.quarantine.LocalQuarantineManager
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.ui.components.EmptyState
import com.vibesync.antivirus.ui.components.SecurityStatusCard
import com.vibesync.antivirus.ui.components.SectionHeader
import com.vibesync.antivirus.ui.components.StatusChip
import com.vibesync.antivirus.ui.components.StatusKind
import java.io.File
import java.text.DateFormat
import java.util.Date
@Composable fun SafeMobileTheme(content: @Composable () -> Unit) {
 val context = LocalContext.current
 val prefs = remember(context) { context.getSharedPreferences(AppearancePreferences.PREFS_NAME, Context.MODE_PRIVATE) }
 var themeMode by remember { mutableStateOf(prefs.getString(AppearancePreferences.THEME_KEY, "dark") ?: "dark") }
 DisposableEffect(prefs) {
  val listener = android.content.SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
   if (key == AppearancePreferences.THEME_KEY) themeMode = prefs.getString(AppearancePreferences.THEME_KEY, "dark") ?: "dark"
  }
  prefs.registerOnSharedPreferenceChangeListener(listener)
  onDispose { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
 }
 val dark = when (themeMode) { "dark" -> true; "light" -> false; else -> isSystemInDarkTheme() }
 MaterialTheme(
  colorScheme = if (dark) com.vibesync.antivirus.ui.theme.SafeMobileDarkColorScheme else com.vibesync.antivirus.ui.theme.SafeMobileLightColorScheme,
  typography = com.vibesync.antivirus.ui.theme.SafeMobileTypography,
  shapes = com.vibesync.antivirus.ui.theme.SafeMobileShapes,
  content = content
 )
}
@Composable fun SafeMobileScreen(repository:ThreatRepository,adsEnabled:Boolean,privacyOptionsRequired:Boolean, sharedText:String? = null, onSharedTextConsumed:() -> Unit = {}) {
 val context=LocalContext.current
 val safeMobileApp=context.applicationContext as SafeMobileApp
 val activity=context as? Activity
 val vm:SafeMobileViewModel=viewModel(factory=SafeMobileViewModel.Factory(repository))
 val state by vm.state.collectAsStateWithLifecycle()
 val auditEntries by repository.observeRecentAudits().collectAsStateWithLifecycle(initialValue = emptyList())
 var selectedDestination by remember { mutableStateOf("home") }
 val onboardingPrefs = remember(context) { context.getSharedPreferences(OnboardingPrefs.NAME, Context.MODE_PRIVATE) }
 var onboardingComplete by remember(context) { mutableStateOf(onboardingPrefs.getBoolean(OnboardingPrefs.COMPLETED, false)) }
 var onboardingStep by remember(context) { mutableStateOf(onboardingPrefs.getInt(OnboardingPrefs.STEP, 0).coerceIn(0, 3)) }
 var storageAccessGranted by remember(context) { mutableStateOf(hasSharedStorageAccess(context)) }
 var notificationsGranted by remember(context) { mutableStateOf(hasNotificationAccess(context)) }
 var sentinelOptIn by remember(context) { mutableStateOf(onboardingPrefs.getBoolean(OnboardingPrefs.SENTINEL_OPT_IN, false)) }
 var languageMenuExpanded by remember { mutableStateOf(false) }
 var featureMenuExpanded by remember { mutableStateOf(false) }
 var localeOverrideTag by remember { mutableStateOf(LocalePreferences.overrideTag(context)) }
 val statusResource = when {
  state.isScanning -> R.string.scan_running
  state.threatCount > 0 -> R.string.threat_found
  state.suspiciousCount > 0 -> R.string.review_recommended
  state.results.any { it.verdict == ScanVerdict.NOT_SCANNED } -> R.string.verdict_not_scanned
  else -> R.string.scan_status
 }
 val statusTint = when {
  state.isScanning -> MaterialTheme.colorScheme.primary
  state.threatCount > 0 -> MaterialTheme.colorScheme.error
  state.suspiciousCount > 0 -> MaterialTheme.colorScheme.tertiary
  state.results.any { it.verdict == ScanVerdict.NOT_SCANNED } -> MaterialTheme.colorScheme.onSurfaceVariant
  state.lastScanAt == null || state.results.isEmpty() -> MaterialTheme.colorScheme.onSurfaceVariant
  else -> successStatusColor()
 }
 val statusIcon = when {
  state.isScanning -> Icons.Default.Security
  state.threatCount > 0 || state.suspiciousCount > 0 || state.results.any { it.verdict == ScanVerdict.NOT_SCANNED } -> Icons.Default.Warning
  state.lastScanAt == null || state.results.isEmpty() -> Icons.Default.Security
  else -> Icons.Default.CheckCircle
 }
 val lifecycleOwner = LocalLifecycleOwner.current
 val connectivity=remember { ConnectivityMonitor(context) }
 val online by connectivity.online.collectAsStateWithLifecycle()
 var privacyAccepted by remember { mutableStateOf(context.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS,0).getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED,false)) }
 var showPrivacyDisclosure by remember { mutableStateOf(false) }
 var pendingSensitiveAction by remember { mutableStateOf<(() -> Unit)?>(null) }
 val requestPrivacyAcknowledgement: (() -> Unit) -> Unit = { action ->
  if (privacyAccepted) action() else { pendingSensitiveAction = action; showPrivacyDisclosure = true }
 }
 var monitoringRunning by remember(context) { mutableStateOf(isStorageSentinelRunning(context)) }
 val setOnboardingStep: (Int) -> Unit = { step -> onboardingStep = step.coerceIn(0, 3); onboardingPrefs.edit().putInt(OnboardingPrefs.STEP, onboardingStep).apply() }
 var pendingUninstallPackage by remember { mutableStateOf<String?>(null) }
 var showDefinitionImportWarning by remember { mutableStateOf(false) }
 var privacyOptionsVisible by remember { mutableStateOf(privacyOptionsRequired) }
 var pendingQuarantine by remember { mutableStateOf<ScanResult?>(null) }
 var pendingRestoreFile by remember { mutableStateOf<File?>(null) }
 var pendingDeleteFile by remember { mutableStateOf<File?>(null) }
 var showRestoreWarning by remember { mutableStateOf(false) }
 val quarantineManager = remember(context) { LocalQuarantineManager(context) }
 val apkPicker=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri:Uri? -> uri?.let(vm::scanSelected) }
 val definitionsPicker=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri:Uri? -> uri?.let(vm::importOfflineDefinitions) }
 val restorePicker=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri:Uri? ->
  val file = pendingRestoreFile
  if (uri != null && file != null) vm.restoreQuarantinedFile(file, uri)
  pendingRestoreFile = null
 }
 val interstitial=remember(activity,adsEnabled,online) { activity?.let { InterstitialAdController(it,adsEnabled && online) } }
 val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
  notificationsGranted = hasNotificationAccess(context)
  if (notificationsGranted && onboardingStep == 2) setOnboardingStep(3)
 }
 val legacyStorageLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
  storageAccessGranted = hasSharedStorageAccess(context)
  if (storageAccessGranted && onboardingStep == 0) setOnboardingStep(1)
 }
 val requestStorage: () -> Unit = {
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
   runCatching { context.startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + context.packageName))) }
    .onFailure { Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show() }
  } else legacyStorageLauncher.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
 }
 val requestNotifications: () -> Unit = {
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
  else { notificationsGranted = true; if (onboardingStep == 2) setOnboardingStep(3) }
 }
 val enableSentinel: () -> Unit = {
  if (!hasSharedStorageAccess(context)) requestStorage()
  else runCatching { context.startForegroundService(Intent(context, com.vibesync.antivirus.core.observer.StorageSentinelService::class.java)) }
   .onFailure { sentinelOptIn = false; Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show() }
   .onSuccess {
    Handler(Looper.getMainLooper()).postDelayed({
     monitoringRunning = isStorageSentinelRunning(context)
     sentinelOptIn = monitoringRunning
     onboardingPrefs.edit().putBoolean(OnboardingPrefs.SENTINEL_OPT_IN, monitoringRunning).apply()
     if (!monitoringRunning) Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show()
    }, 900L)
   }
 }
 val disableSentinel: () -> Unit = {
  context.stopService(Intent(context, com.vibesync.antivirus.core.observer.StorageSentinelService::class.java))
  monitoringRunning = false; sentinelOptIn = false
  onboardingPrefs.edit().putBoolean(OnboardingPrefs.SENTINEL_OPT_IN, false).apply()
 }
 val finishOnboarding: () -> Unit = {
  onboardingPrefs.edit().putBoolean(OnboardingPrefs.COMPLETED, true).putInt(OnboardingPrefs.STEP, 4).apply()
  onboardingComplete = true
  if (!onboardingPrefs.getBoolean(OnboardingPrefs.FIRST_SCAN_REQUESTED, false)) {
   requestPrivacyAcknowledgement {
    if (!onboardingPrefs.getBoolean(OnboardingPrefs.FIRST_SCAN_REQUESTED, false)) {
     onboardingPrefs.edit().putBoolean(OnboardingPrefs.FIRST_SCAN_REQUESTED, true).apply()
     vm.scanFull()
    }
   }
  }
 }
 DisposableEffect(connectivity) { connectivity.start(); onDispose { connectivity.stop() } }
 DisposableEffect(lifecycleOwner, context) {
  val observer = LifecycleEventObserver { _, event ->
   if (event == Lifecycle.Event.ON_RESUME) {
    monitoringRunning = isStorageSentinelRunning(context)
    storageAccessGranted = hasSharedStorageAccess(context)
    notificationsGranted = hasNotificationAccess(context)
    if (!onboardingComplete && onboardingStep == 0 && storageAccessGranted) setOnboardingStep(1)
    if (!onboardingComplete && onboardingStep == 2 && notificationsGranted) setOnboardingStep(3)
    vm.refreshQuarantine()
    OverlayRiskReviewManager.requestForegroundReview(context)
    pendingUninstallPackage?.let { packageName ->
     vm.refreshInstalledPackage(packageName)
     pendingUninstallPackage = null
    }
   }
  }
  lifecycleOwner.lifecycle.addObserver(observer)
  onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
 }
 LaunchedEffect(adsEnabled,online,interstitial) { if(adsEnabled && online) interstitial?.load() }
 LaunchedEffect(state.completedScans,interstitial,online) { if(state.completedScans>0 && online) interstitial?.showAfterScan(state.completedScans) }
 LaunchedEffect(privacyOptionsRequired) { privacyOptionsVisible = privacyOptionsRequired }
 LaunchedEffect(sharedText) { if (!sharedText.isNullOrBlank()) selectedDestination = "phishing" }
 Surface(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing),color=MaterialTheme.colorScheme.background) {
  if (!onboardingComplete) {
   SecurityOnboardingScreen(
    step=onboardingStep, storageAccessGranted=storageAccessGranted, notificationsGranted=notificationsGranted,
    sentinelOptIn=sentinelOptIn, onRequestStorage=requestStorage,
    onContinueStorage={ setOnboardingStep(1) }, onContinueInstalledApps={ setOnboardingStep(2) },
    onRequestNotifications=requestNotifications, onSkipNotifications={ setOnboardingStep(3) },
    onEnableSentinel=enableSentinel, onDisableSentinel=disableSentinel,
    onFinish=finishOnboarding, onSkipSetup=finishOnboarding
   )
  } else {
  Column(Modifier.fillMaxSize()) {
   Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal=18.dp,vertical=14.dp),verticalArrangement=Arrangement.spacedBy(14.dp)) {
    Row(verticalAlignment=Alignment.CenterVertically) {
     Box(Modifier.size(46.dp).background(MaterialTheme.colorScheme.primaryContainer,RoundedCornerShape(15.dp)),contentAlignment=Alignment.Center) {
      androidx.compose.material3.Icon(Icons.Default.Security,contentDescription=null,tint=MaterialTheme.colorScheme.primary,modifier=Modifier.size(31.dp))
     }
     Column(Modifier.padding(start=10.dp).weight(1f)) {
      Text(stringResource(R.string.brand_title),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Black,color=MaterialTheme.colorScheme.onSurface)
      Text(stringResource(R.string.brand_subtitle),style=MaterialTheme.typography.labelMedium,color=MaterialTheme.colorScheme.primary)
     }
     Box {
      IconButton(onClick = { languageMenuExpanded = true }) {
       androidx.compose.material3.Icon(Icons.Default.Language, contentDescription = stringResource(R.string.language_settings), tint = MaterialTheme.colorScheme.primary)
      }
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
     Box {
      IconButton(onClick = { featureMenuExpanded = true }) {
       androidx.compose.material3.Icon(Icons.Default.MoreVert, contentDescription = stringResource(R.string.features_menu))
      }
      DropdownMenu(expanded = featureMenuExpanded, onDismissRequest = { featureMenuExpanded = false }) {
       listOf(
        "apps" to R.string.nav_apps,
        "sentinel" to R.string.nav_sentinel,
        "analytics" to R.string.nav_analytics,
        "history" to R.string.nav_history,
        "quarantine" to R.string.nav_quarantine,
        "guardian" to R.string.nav_guardian,
        "phishing" to R.string.nav_phishing,
        "cleaner" to R.string.nav_cleaner
       ).forEach { (destination, label) ->
        DropdownMenuItem(
         text = { Text(stringResource(label)) },
         onClick = { selectedDestination = destination; featureMenuExpanded = false }
        )
       }
      }
     }
    }
    if (selectedDestination == "home") {
     val lastScanLabel = state.lastScanAt?.let { DateFormat.getDateTimeInstance().format(Date(it)) }
      ?.let { context.getString(R.string.security_last_scan, it) } ?: stringResource(R.string.security_last_scan_none)
     val ringProgress = if (state.isScanning && state.totalItems > 0) state.processedItems.toFloat() / state.totalItems.toFloat() else null
     SecurityStatusCard(
      status=stringResource(statusResource),
      description=stringResource(if (storageAccessGranted) R.string.security_scan_coverage else R.string.security_limited_storage),
      lastScanLabel=lastScanLabel, threatCount=state.threatCount, signatureCount=state.signatureCount,
      scanning=state.isScanning, progress=ringProgress,
      onScan={ requestPrivacyAcknowledgement { vm.scanFull() } }
     )
     Row(Modifier.fillMaxWidth(), horizontalArrangement=Arrangement.spacedBy(8.dp)) {
      OutlinedButton(onClick={ selectedDestination="apps" }, modifier=Modifier.weight(1f)) { Text(stringResource(R.string.nav_apps)) }
      OutlinedButton(onClick={ selectedDestination="sentinel" }, modifier=Modifier.weight(1f)) { Text(stringResource(R.string.nav_sentinel)) }
      OutlinedButton(onClick={ selectedDestination="analytics" }, modifier=Modifier.weight(1f)) { Text(stringResource(R.string.nav_analytics)) }
     }
     SectionHeader(title=stringResource(R.string.analytics_recent_activity), actionLabel=stringResource(R.string.nav_history), onAction={ selectedDestination="history" })
     if (auditEntries.isEmpty()) EmptyState(title=stringResource(R.string.analytics_no_audits),description=stringResource(R.string.analytics_no_audits_body),
      actionLabel=stringResource(R.string.security_scan_now), onAction={ requestPrivacyAcknowledgement { vm.scanFull() } })
     else auditEntries.take(3).forEach { audit ->
      Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface),shape=RoundedCornerShape(14.dp),modifier=Modifier.fillMaxWidth()) {
       Row(Modifier.padding(12.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)) {
        androidx.compose.material3.Icon(if(audit.verdict==ScanVerdict.THREAT.name) Icons.Default.Warning else Icons.Default.History,
         contentDescription=null,tint=if(audit.verdict==ScanVerdict.THREAT.name) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        Column(Modifier.weight(1f)) {
         Text(audit.packageOrPath,style=MaterialTheme.typography.titleSmall)
         Text(audit.verdict.replace('_',' ').lowercase(),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(audit.scanTimestamp)),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
       }
      }
     }
    }
    if (selectedDestination == "home" && !online) {
     Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant),modifier=Modifier.fillMaxWidth()) {
      Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(6.dp)) {
       Text(stringResource(R.string.ad_offline_title),fontWeight=FontWeight.Bold,color=MaterialTheme.colorScheme.primary)
       Text(stringResource(R.string.ad_offline_body),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurface)
       Text(stringResource(R.string.offline_label),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
       OutlinedButton(onClick={ openSponsor(context) }) { Text(stringResource(R.string.coffee_support)) }
      }
     }
    } else if (selectedDestination == "home") TextButton(onClick={ openSponsor(context) }) { Text(stringResource(R.string.coffee_support)) }
    if (selectedDestination == "scan") {
    Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface),shape=RoundedCornerShape(22.dp),modifier=Modifier.fillMaxWidth()) {
     Column(Modifier.padding(18.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Row(verticalAlignment=Alignment.CenterVertically) {
       androidx.compose.material3.Icon(statusIcon,contentDescription=null,tint=statusTint,modifier=Modifier.size(30.dp))
       Column(Modifier.padding(start=10.dp).weight(1f)) {
        Text(stringResource(statusResource),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold,color=statusTint)
        Text(stringResource(R.string.signature_count,state.signatureCount,state.completedScans),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
       }
      }
      Text(stringResource(R.string.scan_explanation),style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurface)
      if (state.isScanning) {
       if (state.totalItems > 0) {
        LinearProgressIndicator(
         progress = (state.processedItems.toFloat() / state.totalItems.toFloat()).coerceIn(0f, 1f),
         modifier = Modifier.fillMaxWidth()
        )
        Text(
         stringResource(R.string.scan_progress, state.processedItems, state.totalItems),
         style = MaterialTheme.typography.bodySmall,
         color = MaterialTheme.colorScheme.onSurfaceVariant
        )
       } else {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        Text(stringResource(R.string.scan_preparing), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
       }
       TextButton(onClick = vm::cancelScan, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.scan_cancel))
       }
      }
      Button(onClick={ requestPrivacyAcknowledgement { vm.scanFull() } },enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) {
       if(state.isScanning) CircularProgressIndicator(Modifier.size(18.dp),strokeWidth=2.dp,color=MaterialTheme.colorScheme.onPrimary) else androidx.compose.material3.Icon(Icons.Default.Security,contentDescription=null)
       Text(stringResource(if(state.isScanning) R.string.scan_running else R.string.scan_installed),modifier=Modifier.padding(start=8.dp))
      }
      OutlinedButton(onClick={ requestPrivacyAcknowledgement { apkPicker.launch(arrayOf("application/vnd.android.package-archive","application/octet-stream")) } },enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) {
       androidx.compose.material3.Icon(Icons.Default.FolderOpen,contentDescription=null)
       Text(stringResource(R.string.scan_selected),modifier=Modifier.padding(start=8.dp))
      }
      OutlinedButton(onClick={ requestPrivacyAcknowledgement { showDefinitionImportWarning = true } },enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) { Text(stringResource(R.string.import_definitions)) }
     }
    }
    }
    if (selectedDestination == "home" || selectedDestination == "sentinel") {
    Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant),shape=RoundedCornerShape(18.dp),modifier=Modifier.fillMaxWidth()) {
     Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
      Text(stringResource(R.string.monitor_title),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold)
      Text(stringResource(R.string.monitor_explanation),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
      Text(
       stringResource(if (monitoringRunning) R.string.monitor_active else R.string.monitor_inactive),
       style = MaterialTheme.typography.labelLarge,
       color = if (monitoringRunning) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.tertiary
      )
      if (!monitoringRunning) {
       OutlinedButton(onClick={ requestPrivacyAcknowledgement {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) {
         context.startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,Uri.parse("package:"+context.packageName)))
        } else {
         runCatching {
          context.startForegroundService(Intent(context,com.vibesync.antivirus.core.observer.StorageSentinelService::class.java))
         }.onSuccess {
          monitoringRunning = true
          Handler(Looper.getMainLooper()).postDelayed({
           monitoringRunning = isStorageSentinelRunning(context)
          }, 800L)
         }.onFailure {
          monitoringRunning = false
          Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show()
         }
        }
       }},enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) { Text(stringResource(R.string.monitor_button)) }
      } else {
       OutlinedButton(onClick={
        context.stopService(Intent(context,com.vibesync.antivirus.core.observer.StorageSentinelService::class.java))
        monitoringRunning = false
       },enabled=true,modifier=Modifier.fillMaxWidth()) { Text(stringResource(R.string.monitor_stop)) }
      }
      Text(stringResource(R.string.monitor_note),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
     }
    }
    }
    if (selectedDestination == "home") {
     Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface),shape=RoundedCornerShape(18.dp),modifier=Modifier.fillMaxWidth()) {
      Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
       Text(stringResource(R.string.threat_feed_dashboard_title),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold)
       Text(stringResource(R.string.threat_feed_active_count,state.activeThreatIndicatorCount),style=MaterialTheme.typography.bodyMedium)
       val lastSuccessfulSyncAt = state.lastThreatFeedSyncAt
       Text(
        if (lastSuccessfulSyncAt == null) stringResource(R.string.threat_feed_never_synced)
        else stringResource(R.string.threat_feed_last_success,DateFormat.getDateTimeInstance().format(Date(lastSuccessfulSyncAt))),
        style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant
       )
       val feedStatusResource = when(state.threatFeedSyncStatus) {
        "RUNNING" -> R.string.threat_feed_syncing
        "SUCCESS" -> R.string.threat_feed_sync_succeeded
        "RETRY" -> R.string.threat_feed_sync_retry
        "FAILED" -> R.string.threat_feed_sync_failed
        else -> R.string.threat_feed_status_not_available
       }
       Text(stringResource(feedStatusResource),style=MaterialTheme.typography.labelMedium,color=MaterialTheme.colorScheme.onSurfaceVariant)
       state.threatFeedSyncError?.takeIf { it.isNotBlank() }?.let {
        Text(it,style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.tertiary)
       }
       Row(horizontalArrangement=Arrangement.spacedBy(8.dp),modifier=Modifier.fillMaxWidth()) {
        Button(
         onClick = {
          if (state.threatFeedSyncStatus == null && state.lastThreatFeedSyncAt == null && state.activeThreatIndicatorCount == 0) selectedDestination = "settings"
          else vm.requestThreatFeedSync()
         },
         modifier=Modifier.weight(1f)
        ) {
         Text(stringResource(if (state.threatFeedSyncStatus == null && state.lastThreatFeedSyncAt == null && state.activeThreatIndicatorCount == 0) R.string.threat_feed_configure else R.string.threat_feed_sync_now))
        }
        OutlinedButton(onClick={ selectedDestination = "settings" },modifier=Modifier.weight(1f)) {
         Text(stringResource(R.string.threat_feed_manage))
        }
       }
      }
     }
    }
    if (selectedDestination == "home") CoreStrengthsAccordion { destination -> selectedDestination = destination }
    if (selectedDestination == "apps") {
     SectionHeader(title=stringResource(R.string.nav_apps),actionLabel=stringResource(R.string.security_scan_now),onAction={ requestPrivacyAcknowledgement { vm.scanInstalled() } })
     val apps=state.results.filter { it.packageName != null }
     if (apps.isEmpty()) EmptyState(title=stringResource(R.string.apps_inventory_empty),description=stringResource(R.string.apps_inventory_empty_body),
      actionLabel=stringResource(R.string.security_scan_now),onAction={ requestPrivacyAcknowledgement { vm.scanInstalled() } })
     else {
      Text(stringResource(R.string.apps_inventory_count,apps.size),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
      apps.take(80).forEach { result ->
       ScanResultCard(result,
        showUninstall=result.packageName?.let { canOfferUninstall(context,it) } == true && result.verdict in listOf(ScanVerdict.THREAT,ScanVerdict.SUSPICIOUS),
        showQuarantine=false,
        onUninstall={ packageName ->
         val host=activity
         if (canOfferUninstall(context,packageName) && host != null) runCatching {
          pendingUninstallPackage=packageName
          host.startActivity(Intent(Intent.ACTION_DELETE,Uri.parse("package:"+packageName)))
         }.onFailure { pendingUninstallPackage=null; Toast.makeText(context,R.string.monitor_start_failed,Toast.LENGTH_LONG).show() }
        }, onQuarantine={}
       )
      }
     }
    }
    if (selectedDestination == "analytics") ProtectionAnalyticsPanel(
     audits=auditEntries, results=state.results, signatureCount=state.signatureCount,
     activeIndicatorCount=state.activeThreatIndicatorCount, lastScanAt=state.lastScanAt, isScanning=state.isScanning,
     quarantinedCount=state.quarantinedFiles.size, monitoringRunning=monitoringRunning,
     storageAccessGranted=storageAccessGranted, notificationsGranted=notificationsGranted, online=online
    )
    if (selectedDestination == "sentinel") {
     Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
      Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
       Text(stringResource(R.string.sentinel_scope_title),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.SemiBold)
       Text(stringResource(R.string.sentinel_scope_body),style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurfaceVariant)
       StatusChip(stringResource(if(monitoringRunning) R.string.analytics_sentinel_running else R.string.analytics_sentinel_stopped),
        kind=if(monitoringRunning) StatusKind.ACTIVE else StatusKind.WARNING)
      }
     }
    }
    if (selectedDestination == "guardian") GuardianPanel()
    if (selectedDestination == "phishing") PhishingPanel(sharedText, repository) { onSharedTextConsumed() }
    if (selectedDestination == "cleaner") StorageCleanerPanel()
    state.messageResource?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) { Text(stringResource(message),Modifier.padding(14.dp),color=MaterialTheme.colorScheme.onSurface,style=MaterialTheme.typography.bodySmall) } }
    state.messageText?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) { Text(message,Modifier.padding(14.dp),color=MaterialTheme.colorScheme.onSurface,style=MaterialTheme.typography.bodySmall) } }
    if(selectedDestination == "scan" && state.results.isNotEmpty()) {
     Column(verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Text(stringResource(R.string.latest_results),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Bold)
      Text(stringResource(R.string.results_summary,state.results.count{it.verdict==ScanVerdict.THREAT},state.results.count{it.verdict==ScanVerdict.SUSPICIOUS},state.results.count{it.verdict==ScanVerdict.NO_MATCH}),color=MaterialTheme.colorScheme.onSurfaceVariant,style=MaterialTheme.typography.bodySmall)
      val notScannedCount = state.results.count { it.verdict == ScanVerdict.NOT_SCANNED }
      if (notScannedCount > 0) Text("${stringResource(R.string.verdict_not_scanned)}: $notScannedCount", color=MaterialTheme.colorScheme.onSurfaceVariant, style=MaterialTheme.typography.bodySmall)
      state.results.take(80).forEach { result ->
       ScanResultCard(
        result,
        showUninstall = result.packageName != null && result.packageName != context.packageName &&
         result.verdict in listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS),
        showQuarantine = result.sourceUri != null && result.verdict in listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS),
        onUninstall = { packageName ->
         val host = activity
         if (host == null) Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show()
         else runCatching {
          pendingUninstallPackage = packageName
          host.startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName")))
         }.onFailure {
          pendingUninstallPackage = null
          Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show()
         }
        },
        onQuarantine = { pendingQuarantine = result }
       )
      }
     }
    }
    if (selectedDestination == "quarantine") {
    Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant),shape=RoundedCornerShape(18.dp),modifier=Modifier.fillMaxWidth()) {
     Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Text(stringResource(R.string.quarantine_vault_title),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold)
      Text(stringResource(R.string.quarantine_vault_description),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
      if (state.quarantinedFiles.isEmpty()) {
       Text(stringResource(R.string.quarantine_vault_empty),style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurfaceVariant)
      } else {
       state.quarantinedFiles.take(30).forEach { file ->
        Column(
         modifier=Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface,RoundedCornerShape(12.dp)).padding(12.dp),
         verticalArrangement=Arrangement.spacedBy(5.dp)
        ) {
         Text(
          text=runCatching { quarantineManager.displayName(file) }.getOrDefault(file.name),
          style=MaterialTheme.typography.titleSmall,fontWeight=FontWeight.SemiBold,color=MaterialTheme.colorScheme.onSurface
         )
         Text(stringResource(R.string.quarantine_item_size,quarantineManager.displaySize(file)),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
         if (!quarantineManager.isEncrypted(file)) Text(stringResource(R.string.quarantine_legacy_warning),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.tertiary)
         OutlinedButton(
          onClick={ pendingRestoreFile=file; showRestoreWarning=true },
          modifier=Modifier.fillMaxWidth()
         ) { Text(stringResource(R.string.quarantine_restore)) }
         TextButton(
          onClick={ pendingDeleteFile=file },
          modifier=Modifier.fillMaxWidth()
         ) { Text(stringResource(R.string.quarantine_delete),color=MaterialTheme.colorScheme.error) }
        }
       }
       if (state.quarantinedFiles.size > 30) {
        Text(stringResource(R.string.quarantine_vault_limit),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
       }
      }
     }
    }
    }
    if (selectedDestination == "history") ScanHistoryPanel(auditEntries)
    if (selectedDestination == "settings") {
     SafeMobileSettingsPanel(privacyOptionsVisible) {
      activity?.let { host -> ConsentManager.showPrivacyOptions(host) { privacyOptionsVisible = ConsentManager.privacyOptionsRequired(host) } }
     }
    }
    Spacer(Modifier.height(8.dp))
   }
   NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
    val destinations = listOf(
     Triple("home", R.string.nav_home, Icons.Default.Home),
     Triple("scan", R.string.nav_scan, Icons.Default.Search),
     Triple("apps", R.string.nav_apps, Icons.Default.Security),
     Triple("analytics", R.string.nav_analytics, Icons.Default.History),
     Triple("settings", R.string.nav_settings, Icons.Default.SettingsIcon)
    )
    destinations.forEach { destination ->
     NavigationBarItem(
      selected = selectedDestination == destination.first,
      onClick = { selectedDestination = destination.first },
      icon = { androidx.compose.material3.Icon(destination.third, contentDescription = stringResource(destination.second)) },
      label = { Text(stringResource(destination.second)) }
     )
    }
   }
   if(adsEnabled && online) Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(top=4.dp),horizontalAlignment=Alignment.CenterHorizontally) {
    Text(stringResource(R.string.ads_label),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
    BannerAd()
   }
  }
  }
 }
 if (showDefinitionImportWarning) AlertDialog(
  onDismissRequest = { showDefinitionImportWarning = false },
  title = { Text(stringResource(R.string.import_unverified_title)) },
  text = { Text(stringResource(R.string.import_unverified_body)) },
  confirmButton = {
   TextButton(onClick = {
    showDefinitionImportWarning = false
    definitionsPicker.launch(arrayOf("application/json","text/json","text/plain"))
   }) { Text(stringResource(R.string.continue_import)) }
  },
  dismissButton = {
   TextButton(onClick = { showDefinitionImportWarning = false }) { Text(stringResource(R.string.close)) }
  }
 )
 if (showRestoreWarning) AlertDialog(
  onDismissRequest = { showRestoreWarning = false; pendingRestoreFile = null },
  title = { Text(stringResource(R.string.quarantine_restore_confirm_title)) },
  text = { Text(stringResource(R.string.quarantine_restore_confirm_body)) },
  confirmButton = {
   TextButton(onClick = {
    val file = pendingRestoreFile
    showRestoreWarning = false
    if (file != null) {
     runCatching { quarantineManager.displayName(file) }
      .onSuccess { restorePicker.launch(it) }
      .onFailure { Toast.makeText(context, R.string.quarantine_restore_failed, Toast.LENGTH_LONG).show(); pendingRestoreFile = null }
    }
   }) { Text(stringResource(R.string.quarantine_restore)) }
  },
  dismissButton = {
   TextButton(onClick = { showRestoreWarning = false; pendingRestoreFile = null }) { Text(stringResource(R.string.close)) }
  }
 )
 pendingDeleteFile?.let { file ->
  AlertDialog(
   onDismissRequest = { pendingDeleteFile = null },
   title = { Text(stringResource(R.string.quarantine_delete_confirm_title)) },
   text = { Text(stringResource(R.string.quarantine_delete_confirm_body)) },
   confirmButton = {
    TextButton(onClick = {
     vm.deleteQuarantinedFile(file)
     pendingDeleteFile = null
    }) { Text(stringResource(R.string.quarantine_delete), color = MaterialTheme.colorScheme.error) }
   },
   dismissButton = {
    TextButton(onClick = { pendingDeleteFile = null }) { Text(stringResource(R.string.close)) }
   }
  )
 }
 pendingQuarantine?.let { flagged ->
  AlertDialog(
   onDismissRequest={ pendingQuarantine = null },
   title={ Text(stringResource(R.string.quarantine_confirm_title)) },
   text={ Text(stringResource(R.string.quarantine_confirm_body)) },
   confirmButton={ TextButton(onClick={
    val uri = runCatching { Uri.parse(flagged.sourceUri) }.getOrNull()
    if (uri != null) vm.quarantineSelectedFile(uri, flagged.sha256)
    pendingQuarantine = null
   }) { Text(stringResource(R.string.quarantine_confirm_action)) } },
   dismissButton={ TextButton(onClick={ pendingQuarantine = null }) { Text(stringResource(R.string.close)) } }
  )
 }
 if(showPrivacyDisclosure) AlertDialog(
  onDismissRequest={ showPrivacyDisclosure=false; pendingSensitiveAction=null },
  title={ Text(stringResource(R.string.privacy_title)) },
  text={ Text(stringResource(R.string.privacy_body)) },
  confirmButton={ TextButton(onClick={
   context.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS,0).edit().putBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED,true).apply()
   privacyAccepted=true
   safeMobileApp.scheduleMaintenanceSweep()
   showPrivacyDisclosure=false
   val action=pendingSensitiveAction
   pendingSensitiveAction=null
   action?.invoke()
  }) { Text(stringResource(R.string.privacy_accept)) } },
  dismissButton={ TextButton(onClick={ showPrivacyDisclosure=false; pendingSensitiveAction=null }) { Text(stringResource(R.string.close)) } }
 )
}
private fun openSponsor(context: Context) {
 runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(BuildConfig.COFFEE_SUPPORT_URL))) }
  .onFailure { Toast.makeText(context, R.string.sponsor_link_failed, Toast.LENGTH_LONG).show() }
}
@Suppress("DEPRECATION")
private fun isStorageSentinelRunning(context: Context): Boolean {
 val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return false
 return manager.getRunningServices(Int.MAX_VALUE).any {
  it.service.className == "com.vibesync.antivirus.core.observer.StorageSentinelService" && it.foreground
 }
}
@Composable private fun successStatusColor(): Color =
 if (MaterialTheme.colorScheme.background.luminance() < 0.5f) Color(0xFF81C784) else Color(0xFF2E7D32)

@Suppress("DEPRECATION")
private fun appInfoForUninstall(context: Context, packageName: String): android.content.pm.ApplicationInfo? = runCatching {
 if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) context.packageManager.getApplicationInfo(packageName, android.content.pm.PackageManager.ApplicationInfoFlags.of(0))
 else context.packageManager.getApplicationInfo(packageName, 0)
}.getOrNull()
private fun isProtectedSystemPackage(context: Context, packageName: String): Boolean {
 if (packageName == context.packageName) return true
 val flags=appInfoForUninstall(context,packageName)?.flags ?: return false
 return flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
}
private fun canOfferUninstall(context: Context, packageName: String): Boolean {
 if (packageName.isBlank() || packageName == context.packageName) return false
 val flags=appInfoForUninstall(context,packageName)?.flags ?: return false
 return flags and (android.content.pm.ApplicationInfo.FLAG_SYSTEM or android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
}
@Composable private fun ScanResultCard(result:ScanResult,showUninstall:Boolean,showQuarantine:Boolean,onUninstall:(String)->Unit,onQuarantine:()->Unit) {
 val context=LocalContext.current
 val protectedSystem=result.packageName?.let { isProtectedSystemPackage(context,it) } == true
 Column(verticalArrangement=Arrangement.spacedBy(6.dp),modifier=Modifier.fillMaxWidth()) {
  com.vibesync.antivirus.ui.components.ThreatListItem(
   result=result,isProtectedSystemApp=protectedSystem,
   showUninstall=showUninstall && result.packageName?.let { canOfferUninstall(context,it) } == true,
   showQuarantine=showQuarantine,onUninstall=onUninstall,onQuarantine=onQuarantine
  )
  result.scanSessionId?.takeIf { it.isNotBlank() }?.let {
   Text(stringResource(R.string.history_session)+": "+it,modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
  result.threatEventId?.takeIf { it.isNotBlank() }?.let {
   Text(stringResource(R.string.threat_event_ray_id,it),modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
  result.sha256?.let {
   Text(stringResource(R.string.file_hash_label,it.take(24)),modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
 }
}
