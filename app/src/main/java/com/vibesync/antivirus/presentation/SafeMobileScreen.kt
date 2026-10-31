package com.vibesync.antivirus.presentation
import com.vibesync.antivirus.core.locale.SecurityText
import androidx.compose.ui.res.pluralStringResource
import android.app.Activity
import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.ActivityNotFoundException
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
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
import androidx.compose.material.icons.filled.WorkspacePremium
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Settings as SettingsIcon
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import com.vibesync.antivirus.ui.components.CyberCard as Card
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
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.withFrameNanos
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.text.style.TextOverflow
import android.widget.Toast
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.connectivity.ConnectivityMonitor
import com.vibesync.antivirus.core.worker.HashDatabaseSyncScheduler
import com.vibesync.antivirus.core.posture.DevicePostureMonitor
import com.vibesync.antivirus.core.observer.StorageSentinelService
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import com.vibesync.antivirus.core.observer.FullScreenAlertAccess
import com.vibesync.antivirus.core.worker.OverlayRiskReviewManager
import com.vibesync.antivirus.core.locale.LocalePreferences
import com.vibesync.antivirus.core.security.DeviceOwnerManager
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.quarantine.LocalQuarantineManager
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.security.GlobalThreatIntelligenceConsent
import com.vibesync.antivirus.core.security.GlobalThreatIntelligenceDonor
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.ui.components.EmptyState
import com.vibesync.antivirus.ui.components.SecurityStatusCard
import com.vibesync.antivirus.ui.components.SectionHeader
import com.vibesync.antivirus.ui.components.StatusChip
import com.vibesync.antivirus.ui.components.StatusKind
import java.io.File
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.launch
@Composable fun SafeMobileTheme(
 theme: com.vibesync.antivirus.ui.theme.AppTheme = com.vibesync.antivirus.ui.theme.AppTheme.MIDNIGHT,
 content: @Composable () -> Unit
) { com.vibesync.antivirus.ui.theme.SafeMobileMaterialTheme(theme = theme, content = content) }
@Composable fun SafeMobileScreen(
 repository:ThreatRepository,
  batteryStatusEpoch: Int = 0,
  appTheme: com.vibesync.antivirus.ui.theme.AppTheme = com.vibesync.antivirus.ui.theme.AppTheme.MIDNIGHT,
  onAppThemeChanged: (com.vibesync.antivirus.ui.theme.AppTheme) -> Unit = {},
 sharedText:String? = null,
 onSharedTextConsumed:() -> Unit = {},
 openQuarantine:Boolean = false,
 onOpenQuarantineConsumed:() -> Unit = {},
 openDevicePosture:Boolean = false,
 onOpenDevicePostureConsumed:() -> Unit = {}
) {
 val context=LocalContext.current
 val safeMobileApp=context.applicationContext as SafeMobileApp
 var fullScreenAlertsGranted by remember(context) { mutableStateOf(FullScreenAlertAccess.isGranted(context)) }
 val activity=context as? Activity
 val vm:SafeMobileViewModel=viewModel(factory=SafeMobileViewModel.Factory(repository))
 val state by vm.state.collectAsStateWithLifecycle()
 val postureVm:DevicePostureViewModel=viewModel(factory=DevicePostureViewModel.Factory(safeMobileApp.devicePostureRepository))
 val postureState by postureVm.state.collectAsStateWithLifecycle()
 val initialHashSyncPending by androidx.compose.runtime.produceState(initialValue = false, context) {
  HashDatabaseSyncScheduler.initialSyncPending(context).collect { value = it }
 }
 val auditEntries by repository.observeRecentAudits().collectAsStateWithLifecycle(initialValue = emptyList())
 val securityIncidents by repository.observeRecentSecurityIncidents().collectAsStateWithLifecycle(initialValue = emptyList())
 val ownerManager = remember(context) { DeviceOwnerManager(context) }
 var selectedDestination by remember { mutableStateOf("home") }
 val contentScrollState = rememberScrollState()
 var folderUris by remember(context) { mutableStateOf(StorageAccessPreferences.accessibleTreeUris(context)) }
 var pendingFolderRole by remember { mutableStateOf(StorageAccessPreferences.DOWNLOADS) }
 var showPlayProtectDialog by remember { mutableStateOf(false) }
 LaunchedEffect(selectedDestination) { contentScrollState.scrollTo(0) }
 LaunchedEffect(state.scanSummary?.completedAt) {
  if (state.scanSummary != null && selectedDestination == "home") contentScrollState.animateScrollTo(0)
 }
 val onboardingPrefs = remember(context) { context.getSharedPreferences(OnboardingPrefs.NAME, Context.MODE_PRIVATE) }


 var onboardingComplete by remember(context) { mutableStateOf(onboardingPrefs.getBoolean(
  OnboardingPrefs.COMPLETED,
  context.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS, Context.MODE_PRIVATE)
   .getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED, false)
 )) }
 var storageAccessGranted by remember(context) { mutableStateOf(hasSharedStorageAccess(context)) }
 var notificationsGranted by remember(context) { mutableStateOf(hasNotificationAccess(context)) }
 var sentinelOptIn by remember(context) { mutableStateOf(onboardingPrefs.getBoolean(OnboardingPrefs.SENTINEL_OPT_IN, isStorageSentinelRunning(context))) }
 var languageMenuExpanded by remember { mutableStateOf(false) }
 var featureMenuExpanded by remember { mutableStateOf(false) }
 var localeOverrideTag by remember { mutableStateOf(LocalePreferences.overrideTag(context)) }
 val statusResource = when {
  state.isScanning -> R.string.scan_running
  state.threatCount > 0 -> R.string.threat_found
  state.suspiciousCount > 0 -> R.string.review_recommended
  state.results.any { it.verdict == ScanVerdict.NOT_SCANNED } -> R.string.verdict_not_scanned
  state.scanSummary != null -> R.string.scan_complete
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
 val connected by connectivity.online.collectAsStateWithLifecycle()
 val online = BuildConfig.OPTIONAL_FEED_ENABLED && connected
 var privacyAccepted by remember { mutableStateOf(context.getSharedPreferences(SafeMobileApp.PRIVACY_PREFS,0).getBoolean(SafeMobileApp.PRIVACY_ACKNOWLEDGED,false)) }
 LaunchedEffect(privacyAccepted) {
  if (privacyAccepted) com.vibesync.antivirus.core.observer.InstallSentinelService.startFromVisibleUi(context)
 }
 LaunchedEffect(selectedDestination, privacyAccepted) {
  if (selectedDestination == "apps" && privacyAccepted) vm.refreshInstalledInventory()
 }
 var showPrivacyDisclosure by remember { mutableStateOf(false) }
 var pendingSensitiveAction by remember { mutableStateOf<(() -> Unit)?>(null) }
 val requestPrivacyAcknowledgement: (() -> Unit) -> Unit = { action ->
  if (privacyAccepted) action() else { pendingSensitiveAction = action; showPrivacyDisclosure = true }
 }
 var monitoringRunning by remember(context) { mutableStateOf(isStorageSentinelRunning(context) && hasSharedStorageAccess(context)) }
 var pendingUninstallPackage by remember { mutableStateOf<String?>(null) }
 var showNotificationPermissionPrompt by remember { mutableStateOf(false) }
  val notificationPermissionPromptKey = "notification_permission_first_prompted"
 var showStoragePermissionPrompt by remember { mutableStateOf(false) }
 var pendingAlertEnable by remember { mutableStateOf(false) }
 var pendingSentinelEnable by remember { mutableStateOf(false) }
 val securityPrefs = remember(context) { context.getSharedPreferences(SafeMobileApp.SECURITY_PREFS, Context.MODE_PRIVATE) }
 var sentinelDesired by remember(context) { mutableStateOf(securityPrefs.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false)) }
 var strictMode by remember(context) { mutableStateOf(securityPrefs.getBoolean(SafeMobileApp.KEY_STRICT_MODE, false)) }
 var securityAlertsEnabled by remember(context) { mutableStateOf(securityPrefs.getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)) }
 val snackbarHostState = remember { SnackbarHostState() }
 val uiScope = rememberCoroutineScope()
 var pendingGlobalDonationResults by remember { mutableStateOf<List<ScanResult>>(emptyList()) }
 val promptedGlobalDonationEvents = remember { mutableSetOf<String>() }
 LaunchedEffect(state.results) {
  if (!GlobalThreatIntelligenceConsent.isEnabled(context) ||
      selectedDestination !in setOf("home", "scan", "apps")) return@LaunchedEffect
  val additions = state.results.filter { result ->
   result.verdict == ScanVerdict.THREAT &&
    result.sha256?.matches(Regex("[0-9a-f]{64}")) == true &&
    (result.sourceLocalPath != null || result.sourceUri != null || result.packageName != null) &&
    result.threatEventId?.let { it !in promptedGlobalDonationEvents } == true
  }
  additions.forEach { it.threatEventId?.let(promptedGlobalDonationEvents::add) }
  if (additions.isNotEmpty()) pendingGlobalDonationResults = pendingGlobalDonationResults + additions
 }
 var lastUninstallPackage by remember { mutableStateOf<String?>(null) }
 val showUninstallSnackbar: (String, String?) -> Unit = { message, appInfoPackage ->
  uiScope.launch {
   val result = snackbarHostState.showSnackbar(
    message = message,
    actionLabel = if (appInfoPackage != null) context.getString(R.string.activity_not_found_action) else null
   )
   if (result == SnackbarResult.ActionPerformed && appInfoPackage != null) {
    try { context.startActivity(UninstallHandler.buildAppInfoIntent(appInfoPackage)) }
    catch (e: ActivityNotFoundException) { Toast.makeText(context, R.string.uninstall_no_settings, Toast.LENGTH_LONG).show() }
    catch (e: SecurityException) { Toast.makeText(context, R.string.uninstall_no_settings, Toast.LENGTH_LONG).show() }
   }
  }
 }
 val deleteLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
  lastUninstallPackage?.let { vm.refreshInstalledPackage(it) }
  lastUninstallPackage = null
  pendingUninstallPackage = null
  val message = if (result.resultCode == Activity.RESULT_OK) R.string.uninstall_complete else R.string.uninstall_cancelled
  showUninstallSnackbar(context.getString(message), null)
 }
 var showDefinitionImportWarning by remember { mutableStateOf(false) }
 var pendingQuarantine by remember { mutableStateOf<ScanResult?>(null) }
 var pendingRestoreFile by remember { mutableStateOf<File?>(null) }
 var pendingDeleteFile by remember { mutableStateOf<File?>(null) }
 var showRestoreWarning by remember { mutableStateOf(false) }
 val quarantineManager = remember(context) { LocalQuarantineManager(context) }
 val apkPicker=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri:Uri? -> uri?.let(vm::scanSelected) }
 val definitionsPicker=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri:Uri? -> uri?.let(vm::importOfflineDefinitions) }
  val pendingYaraPicker=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri:Uri? -> uri?.let(vm::importPendingYaraRule) }
 val restorePicker=rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri:Uri? ->
  val file = pendingRestoreFile
  if (uri != null && file != null) vm.restoreQuarantinedFile(file, uri)
  pendingRestoreFile = null
 }
 val notificationLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
  notificationsGranted = hasNotificationAccess(context)
  if (pendingAlertEnable) {
   securityAlertsEnabled = notificationsGranted
   securityPrefs.edit().putBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, notificationsGranted).apply()
   pendingAlertEnable = false
   if (notificationsGranted && privacyAccepted) DevicePostureMonitor.enqueueNow(context)
  }
 }
 val storageTreeLauncher = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) folderResult@{ result ->
  val uri = result.data?.data
  if (result.resultCode != Activity.RESULT_OK || uri == null) {
   pendingSentinelEnable = false
   selectedDestination = "home"
   return@folderResult
  }
  if (StorageAccessPreferences.isStorageRoot(uri)) {
   Toast.makeText(context, R.string.ui_storage_root_blocked, Toast.LENGTH_LONG).show()
   pendingSentinelEnable = false
   selectedDestination = "home"
   return@folderResult
  }
  val role = pendingFolderRole
  val grantFlags = result.data?.flags ?: Intent.FLAG_GRANT_READ_URI_PERMISSION
  uiScope.launch {
   val granted = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
    runCatching { StorageAccessPreferences.persistSelectedFolder(context, uri, role, grantFlags) }.getOrDefault(false)
   }
   pendingSentinelEnable = false
   folderUris = StorageAccessPreferences.accessibleTreeUris(context)
   storageAccessGranted = folderUris.isNotEmpty()
   if (granted) {
    securityPrefs.edit().putBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, true).apply()
    sentinelDesired = true
    sentinelOptIn = true
    runCatching { context.startForegroundService(Intent(context, StorageSentinelService::class.java)) }
     .onFailure { Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show() }
    Handler(Looper.getMainLooper()).postDelayed({ monitoringRunning = isStorageSentinelRunning(context) && hasSharedStorageAccess(context) }, 900L)
   } else {
    Toast.makeText(context, R.string.ui_folder_access_not_granted, Toast.LENGTH_LONG).show()
    selectedDestination = "home"
   }
  }
 }
 val requestStorage: () -> Unit = { selectedDestination = "sentinel" }
 val enableSentinel: () -> Unit = {
  if (!hasSharedStorageAccess(context)) requestStorage()
  else runCatching { context.startForegroundService(Intent(context, StorageSentinelService::class.java)) }
   .onSuccess {
    securityPrefs.edit().putBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, true).apply()
    sentinelDesired = true
    sentinelOptIn = true
    Handler(Looper.getMainLooper()).postDelayed({
     storageAccessGranted = hasSharedStorageAccess(context)
     monitoringRunning = isStorageSentinelRunning(context) && storageAccessGranted
    }, 900L)
   }
   .onFailure {
    securityPrefs.edit().putBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false).apply()
    sentinelDesired = false
    sentinelOptIn = false
    Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show()
   }
 }
 val disableSentinel: () -> Unit = {
  securityPrefs.edit().putBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false).apply()
  context.stopService(Intent(context, StorageSentinelService::class.java))
  monitoringRunning = false; sentinelOptIn = false; sentinelDesired = false
  onboardingPrefs.edit().putBoolean(OnboardingPrefs.SENTINEL_OPT_IN, false).apply()
 }
 val toggleProtection: (Boolean) -> Unit = { enabled -> if (enabled) enableSentinel() else disableSentinel() }
 val changeSecurityAlerts: (Boolean) -> Unit = { enabled ->
  if (!enabled) {
   pendingAlertEnable = false
   securityAlertsEnabled = false
   securityPrefs.edit().putBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false).apply()
  } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !hasNotificationAccess(context)) {
   pendingAlertEnable = true
   showNotificationPermissionPrompt = true
  } else {
   securityAlertsEnabled = true
   securityPrefs.edit().putBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, true).apply()
   if (privacyAccepted) DevicePostureMonitor.enqueueNow(context)
  }
 }
 val updateStrictMode: (Boolean) -> Unit = { enabled ->
  strictMode = enabled
  securityPrefs.edit().putBoolean(SafeMobileApp.KEY_STRICT_MODE, enabled).apply()
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
 DisposableEffect(lifecycleOwner, context, privacyAccepted) {
  val observer = LifecycleEventObserver { _, event ->
   if (event == Lifecycle.Event.ON_RESUME) {
    if (privacyAccepted) vm.refreshTrustOverrides()
    fullScreenAlertsGranted = FullScreenAlertAccess.isGranted(context)
    storageAccessGranted = hasSharedStorageAccess(context)
    folderUris = StorageAccessPreferences.accessibleTreeUris(context)
    vm.refreshSecurityScore()
    if (privacyAccepted) postureVm.refresh()
    ownerManager.refreshState()
    sentinelDesired = securityPrefs.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false)
    sentinelOptIn = sentinelDesired
    strictMode = securityPrefs.getBoolean(SafeMobileApp.KEY_STRICT_MODE, false)
    securityAlertsEnabled = securityPrefs.getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)
    monitoringRunning = isStorageSentinelRunning(context) && storageAccessGranted
    if (!storageAccessGranted && isStorageSentinelRunning(context)) {
     context.stopService(Intent(context, StorageSentinelService::class.java))
     monitoringRunning = false
    } else if (sentinelDesired && storageAccessGranted && !monitoringRunning) {
     runCatching { context.startForegroundService(Intent(context, StorageSentinelService::class.java)) }
      .onFailure { Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show() }
     Handler(Looper.getMainLooper()).postDelayed({
      monitoringRunning = isStorageSentinelRunning(context) && hasSharedStorageAccess(context)
     }, 700L)
    }
    notificationsGranted = hasNotificationAccess(context)
    vm.refreshQuarantine()
    OverlayRiskReviewManager.requestForegroundReview(context)
    pendingUninstallPackage?.let { packageName -> vm.refreshInstalledPackage(packageName); pendingUninstallPackage = null }
   }
  }
  lifecycleOwner.lifecycle.addObserver(observer)
  onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
 }
 LaunchedEffect(onboardingComplete, privacyAccepted) {
  // Explain and request notifications on the first consented launch on Android 13+.
  if (onboardingComplete && privacyAccepted && Build.VERSION.SDK_INT >= 33 &&
      !notificationsGranted && !securityPrefs.getBoolean(notificationPermissionPromptKey, false)) {
    securityPrefs.edit().putBoolean(notificationPermissionPromptKey, true).apply()
    // Respect any prior opt-out. The Android permission grant must not enable alerts without consent.
    pendingAlertEnable = securityPrefs.getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)
    showNotificationPermissionPrompt = true
  }
  if (privacyAccepted) postureVm.refresh()
  if (onboardingComplete && privacyAccepted &&
      !onboardingPrefs.getBoolean(OnboardingPrefs.FIRST_SCAN_REQUESTED, false)) {
   onboardingPrefs.edit().putBoolean(OnboardingPrefs.FIRST_SCAN_REQUESTED, true).apply()
   vm.scanFull()
  }
 }
 LaunchedEffect(initialHashSyncPending) {
  if (!initialHashSyncPending) { vm.refreshHashDatabaseCapability(); vm.refreshSecurityScore() }
 }
 LaunchedEffect(lifecycleOwner, privacyAccepted) {
  lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
   while (true) {
    fullScreenAlertsGranted = FullScreenAlertAccess.isGranted(context)
    folderUris = StorageAccessPreferences.accessibleTreeUris(context)
    storageAccessGranted = folderUris.isNotEmpty()
    monitoringRunning = isStorageSentinelRunning(context) && storageAccessGranted
    vm.refreshSecurityScore()
    if (privacyAccepted) postureVm.refresh(force = false)
    kotlinx.coroutines.delay(30_000L)
   }
  }
 }
 LaunchedEffect(sharedText) { if (!sharedText.isNullOrBlank()) selectedDestination = "phishing" }
 LaunchedEffect(openQuarantine) {
  if (openQuarantine) {
   selectedDestination = "quarantine"
   onOpenQuarantineConsumed()
  }
 }
 LaunchedEffect(openDevicePosture) {
  if (openDevicePosture) {
   selectedDestination = "posture"
   if (privacyAccepted) postureVm.refresh()
   onOpenDevicePostureConsumed()
  }
 }
 LaunchedEffect(state.messageResource) {
  if (state.messageResource == R.string.quarantine_delete_failed) {
   Toast.makeText(context, R.string.quarantine_delete_failed, Toast.LENGTH_LONG).show()
  }
 }
 Surface(Modifier.fillMaxSize(),color=MaterialTheme.colorScheme.background) {
  if (!onboardingComplete) {
   SecurityOnboardingScreen(
    initialSyncPending=initialHashSyncPending,
    onFinish=finishOnboarding,
    onSkipSetup=finishOnboarding
   )
  } else {
   Column(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
   Column(Modifier.weight(1f).verticalScroll(contentScrollState).padding(horizontal=18.dp,vertical=14.dp),verticalArrangement=Arrangement.spacedBy(14.dp)) {
    Row(verticalAlignment=Alignment.CenterVertically) {
     Box(Modifier.size(46.dp).background(MaterialTheme.colorScheme.primaryContainer,RoundedCornerShape(15.dp)),contentAlignment=Alignment.Center) {
      androidx.compose.material3.Icon(painterResource(R.drawable.ic_launcher_foreground),contentDescription=stringResource(R.string.app_name),tint=Color.Unspecified,modifier=Modifier.size(35.dp))
     }
     Column(Modifier.padding(start=10.dp).weight(1f)) {
      Text(stringResource(R.string.brand_title),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Black,color=MaterialTheme.colorScheme.onSurface)
      Text(stringResource(R.string.brand_subtitle),style=MaterialTheme.typography.labelMedium,color=MaterialTheme.colorScheme.primary)
     }
     IconButton(onClick = { selectedDestination = "pro" }) {
      androidx.compose.material3.Icon(Icons.Default.WorkspacePremium,
       contentDescription = stringResource(R.string.pro_title), tint = MaterialTheme.colorScheme.primary)
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
        "sources" to R.string.nav_install_sources,
        "sentinel" to R.string.nav_sentinel,
        "posture" to R.string.posture_title,
        "analytics" to R.string.nav_analytics,
        "history" to R.string.nav_history,
        "quarantine" to R.string.nav_quarantine,
        "guardian" to R.string.nav_guardian,
        "phishing" to R.string.nav_phishing,
        "cleaner" to R.string.nav_cleaner,
         "capabilities" to R.string.detection_capabilities_title,
         "pro" to R.string.pro_title
       ).forEach { (destination, label) ->
        DropdownMenuItem(
         text = { Text(stringResource(label)) },
         onClick = { selectedDestination = destination; featureMenuExpanded = false }
        )
       }
      }
     }
    }
    if (privacyAccepted && !notificationsGranted && Build.VERSION.SDK_INT >= 33) {
       Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
         Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
           Text(stringResource(R.string.ui_notifications_denied), color = MaterialTheme.colorScheme.onErrorContainer)
           OutlinedButton(onClick = {
             val settings = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                 Uri.parse("package:" + context.packageName))
             runCatching { context.startActivity(settings) }.onFailure {
               Toast.makeText(context, R.string.ui_notifications_settings_unavailable, Toast.LENGTH_LONG).show()
             }
           }) { Text(stringResource(R.string.ui_enable_notifications_settings)) }
         }
       }
     }
     if (selectedDestination == "home" || selectedDestination == "scan") {
     if (selectedDestination == "home") {
      if (!fullScreenAlertsGranted) FullScreenAlertPermissionCard(onOpenSettings = {
       runCatching { FullScreenAlertAccess.settingsIntent(context)?.let(context::startActivity) }
        .onFailure { Toast.makeText(context, R.string.full_screen_settings_unavailable, Toast.LENGTH_LONG).show() }
      })
      SystemAppProtectionBadge()
      BatteryOptimizationCard(batteryStatusEpoch)
     }
     ScanFeedbackCard(state,
      onResults = { selectedDestination = if (state.results.isEmpty()) "history" else "scan" },
      onCancel = vm::cancelScan)
    }
    if (selectedDestination == "home") {
     DevicePostureDashboardCard(postureState, onOpen = {
      selectedDestination = "posture"
      if (privacyAccepted) postureVm.refresh()
     })
     LimitedProtectionBanner(
      downloads = folderUris.isNotEmpty() && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.DOWNLOADS),
      whatsapp = folderUris.isNotEmpty() && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.WHATSAPP),
      running = monitoringRunning, onSetup = { selectedDestination = "sentinel" })
     SecurityDashboard(state.securityAssessment,
      onCheckPlayProtect = { requestPrivacyAcknowledgement { showPlayProtectDialog = true } },
      onSync = { vm.requestHashDatabaseSync() })
     HomeSecurityMetrics(
      summary = state.scanSummary,
      hashDbPublishedAt = com.vibesync.antivirus.core.hashdb.HashDatabaseFreshness.updatedAt(context, state.hashDatabaseCapability.version)
     )
     if (initialHashSyncPending) {
      Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.primaryContainer),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
       Row(Modifier.padding(14.dp), horizontalArrangement=Arrangement.spacedBy(10.dp), verticalAlignment=Alignment.CenterVertically) {
        CircularProgressIndicator(Modifier.size(18.dp), strokeWidth=2.dp)
        Text(stringResource(R.string.hash_database_initial_syncing), style=MaterialTheme.typography.bodyMedium)
       }
      }
     }
     Button(onClick = { requestPrivacyAcknowledgement { vm.scanFull() } }, enabled = !state.isScanning, modifier = Modifier.fillMaxWidth()) {
      androidx.compose.material3.Icon(Icons.Default.Security, contentDescription = null)
      Text(stringResource(R.string.security_scan_now), Modifier.padding(start = 8.dp))
     }
     AnalyticsCharts(repository, state.results)
     SectionHeader(title=stringResource(R.string.analytics_recent_activity), actionLabel=stringResource(R.string.nav_history), onAction={ selectedDestination="history" })
     if (auditEntries.isEmpty()) EmptyState(title=stringResource(R.string.analytics_no_audits),description=stringResource(R.string.analytics_no_audits_body))
     else auditEntries.take(3).forEach { audit ->
      Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
       Row(Modifier.padding(12.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)) {
        androidx.compose.material3.Icon(if(audit.verdict==ScanVerdict.THREAT.name) Icons.Default.Warning else Icons.Default.History,
         contentDescription=null,tint=if(audit.verdict==ScanVerdict.THREAT.name) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary)
        Column(Modifier.weight(1f)) {
         Text(audit.packageOrPath,style=MaterialTheme.typography.titleSmall)
         Text(stringResource(SecurityText.verdict(audit.verdict)),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(localizedDate(audit.scanTimestamp, timeOnly = true),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
       }
      }
     }
    }
    if (selectedDestination == "sources") {
     InstallSourceAuditPanel(
      incidents = securityIncidents,
      onScan = { requestPrivacyAcknowledgement { vm.scanInstalled() } },
      onInspect = { packageName ->
       try { context.startActivity(UninstallHandler.buildAppInfoIntent(packageName)) }
       catch (_: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
       catch (_: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
      },
      onUninstall = { packageName ->
       lastUninstallPackage = packageName
       pendingUninstallPackage = packageName
       when (vm.requestUninstall(
        context, packageName,
        launchDelete = { intent -> deleteLauncher.launch(intent) },
        openAppInfo = { intent -> context.startActivity(intent) }
       )) {
        UninstallResult.Success, UninstallResult.RequiresUserAction -> Unit
        is UninstallResult.BlockedSystemApp -> showUninstallSnackbar(context.getString(R.string.uninstall_protected), packageName)
        UninstallResult.NotFound -> showUninstallSnackbar(context.getString(R.string.uninstall_not_found), null)
        UninstallResult.OpenedAppInfo -> showUninstallSnackbar(context.getString(R.string.uninstall_opened_app_info), null)
        UninstallResult.HandlerUnavailable -> showUninstallSnackbar(context.getString(R.string.uninstall_launch_failed), packageName)
       }
      }
     )
    }
    if (selectedDestination == "scan") {
    Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
     Column(Modifier.padding(18.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Row(verticalAlignment=Alignment.CenterVertically) {
       androidx.compose.material3.Icon(statusIcon,contentDescription=null,tint=statusTint,modifier=Modifier.size(30.dp))
       Column(Modifier.padding(start=10.dp).weight(1f)) {
        Text(stringResource(statusResource),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold,color=statusTint)
        Text(stringResource(R.string.signature_count,state.signatureCount,state.completedScans),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
       }
      }
      Text(stringResource(R.string.scan_explanation),style=MaterialTheme.typography.bodyMedium,color=MaterialTheme.colorScheme.onSurface)
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
    if (selectedDestination == "home") CoreStrengthsAccordion { destination -> selectedDestination = destination }
    if (selectedDestination == "apps") {
     SectionHeader(title=stringResource(R.string.nav_apps),actionLabel=stringResource(R.string.security_scan_now),onAction={ requestPrivacyAcknowledgement { vm.scanInstalled() } })
     val apps=state.results.filter { it.packageName != null }
     if (state.isScanning) {
       LinearProgressIndicator(modifier=Modifier.fillMaxWidth())
       Text(stringResource(R.string.apps_scanning_in_progress), style=MaterialTheme.typography.bodySmall)
      }
      if (state.inventoryLoading) CircularProgressIndicator()
      if (apps.isEmpty() && state.installedApps.isNotEmpty()) {
       Text(pluralStringResource(R.plurals.l10n_apps, state.installedApps.size, state.installedApps.size), style=MaterialTheme.typography.bodyMedium)
       state.installedApps.take(80).forEach { item ->
        Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface), modifier=Modifier.fillMaxWidth()) {
         Row(Modifier.fillMaxWidth().padding(12.dp), verticalAlignment=Alignment.CenterVertically, horizontalArrangement=Arrangement.spacedBy(8.dp)) {
          Column(Modifier.weight(1f)) {
           Text(item.displayName, style=MaterialTheme.typography.titleSmall)
           Text(item.packageName, style=MaterialTheme.typography.labelSmall, color=MaterialTheme.colorScheme.onSurfaceVariant)
          }
          TextButton(onClick={ runCatching { context.startActivity(UninstallHandler.buildAppInfoIntent(item.packageName)) }
            .onFailure { Toast.makeText(context,R.string.uninstall_no_settings,Toast.LENGTH_SHORT).show() } }) {
           Text(stringResource(R.string.app_info_label))
          }
         }
        }
       }
      } else if (apps.isEmpty()) EmptyState(title=stringResource(R.string.apps_inventory_empty),description=stringResource(if(state.inventoryLoaded) R.string.apps_no_user_installed else R.string.apps_inventory_empty_body),
      actionLabel=stringResource(R.string.security_scan_now),onAction={ requestPrivacyAcknowledgement { vm.scanInstalled() } })
     else {
      Text(pluralStringResource(R.plurals.l10n_apps, apps.size, apps.size),style=MaterialTheme.typography.bodySmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
      apps.take(80).forEach { result ->
       ScanResultCard(
        result,
        showUninstall = result.packageName?.let { canOfferUninstall(context,it) } == true,
        showQuarantine = false,
        showAppInfo = true,
        onUninstall = { packageName ->
         lastUninstallPackage = packageName
         pendingUninstallPackage = packageName
         when (vm.requestUninstall(context, packageName,
          launchDelete = { intent -> deleteLauncher.launch(intent) },
          openAppInfo = { intent -> context.startActivity(intent) })) {
          UninstallResult.Success, UninstallResult.RequiresUserAction -> Unit
          is UninstallResult.BlockedSystemApp -> {
           showUninstallSnackbar(context.getString(R.string.uninstall_protected), null)
           try { context.startActivity(UninstallHandler.buildAppInfoIntent(packageName)) }
           catch (e: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
           catch (e: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
          }
          UninstallResult.NotFound -> {
           pendingUninstallPackage = null; lastUninstallPackage = null
           showUninstallSnackbar(context.getString(R.string.uninstall_not_found), null)
          }
          UninstallResult.OpenedAppInfo -> showUninstallSnackbar(context.getString(R.string.uninstall_opened_app_info), packageName)
          UninstallResult.HandlerUnavailable -> {
           pendingUninstallPackage = null
           showUninstallSnackbar(context.getString(R.string.uninstall_launch_failed), packageName)
          }
         }
        },
        onAppInfo = { packageName ->
         try { context.startActivity(UninstallHandler.buildAppInfoIntent(packageName)) }
         catch (e: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
         catch (e: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
        },
        onQuarantine = {}, onTrust = { vm.trustApp(it) }, onRemoveTrust = vm::removeTrust
       )
      }
     }
    }
    if (selectedDestination == "analytics") AnalyticsCharts(repository)
    if (selectedDestination == "analytics") ProtectionAnalyticsPanel(
     audits=auditEntries, results=state.results, signatureCount=state.signatureCount,
     activeIndicatorCount=state.activeThreatIndicatorCount, lastScanAt=state.lastScanAt, isScanning=state.isScanning,
     quarantinedCount=state.quarantinedFiles.size, monitoringRunning=monitoringRunning,
     storageAccessGranted=storageAccessGranted, notificationsGranted=notificationsGranted, online=online
    )
    if (selectedDestination == "sentinel") {
     SentinelFolderPanel(context, folderUris, monitoringRunning,
      onAdd = { role -> requestPrivacyAcknowledgement {
       pendingFolderRole = role; pendingSentinelEnable = true; showStoragePermissionPrompt = true
      } },
      onRemove = { uri -> uiScope.launch {
       kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { StorageAccessPreferences.removeFolder(context, uri) }
       folderUris = StorageAccessPreferences.accessibleTreeUris(context)
       storageAccessGranted = folderUris.isNotEmpty()
       if (!storageAccessGranted) disableSentinel()
      } },
      onStart = { requestPrivacyAcknowledgement { enableSentinel() } }, onStop = disableSentinel,
      onSkip = { selectedDestination = "home" })
    }
    if (selectedDestination == "guardian") GuardianPanel()
    if (selectedDestination == "posture") DevicePostureScreen(
     state = postureState, alertsAvailable = securityAlertsEnabled && notificationsGranted,
     onRefresh = { requestPrivacyAcknowledgement { postureVm.refresh() } },
     onMonitoringChanged = { enabled ->
      if (enabled) requestPrivacyAcknowledgement { postureVm.setMonitoring(context, true) }
      else postureVm.setMonitoring(context, false)
     },
     onEnableAlerts = { requestPrivacyAcknowledgement { changeSecurityAlerts(true) } }
    )
    if (selectedDestination == "phishing") PhishingPanel(sharedText, repository) { onSharedTextConsumed() }
    if (selectedDestination == "cleaner") StorageCleanerPanel()
    state.messageResource?.takeUnless { it == R.string.scan_complete && selectedDestination in listOf("home", "scan") }?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) { Text(stringResource(message),Modifier.padding(14.dp),color=MaterialTheme.colorScheme.onSurface,style=MaterialTheme.typography.bodySmall) } }
    state.messageText?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) { Text(message.resolve(context),Modifier.padding(14.dp),color=MaterialTheme.colorScheme.onSurface,style=MaterialTheme.typography.bodySmall) } }
    if(selectedDestination == "scan" && state.results.isNotEmpty()) {
     Column(verticalArrangement=Arrangement.spacedBy(10.dp)) {
      Text(stringResource(R.string.latest_results),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Bold)
      Text(listOf(pluralStringResource(R.plurals.l10n_threats, state.threatCount, state.threatCount), pluralStringResource(R.plurals.l10n_review, state.suspiciousCount, state.suspiciousCount), state.results.count { it.verdict == ScanVerdict.NO_MATCH }.let { pluralStringResource(R.plurals.l10n_no_match, it, it) }).joinToString(" · "),color=MaterialTheme.colorScheme.onSurfaceVariant,style=MaterialTheme.typography.bodySmall)
      val notScannedCount = state.results.count { it.verdict == ScanVerdict.NOT_SCANNED }
      if (notScannedCount > 0) Text(pluralStringResource(R.plurals.l10n_unreadable, notScannedCount, notScannedCount), color=MaterialTheme.colorScheme.onSurfaceVariant, style=MaterialTheme.typography.bodySmall)
      state.results.take(80).forEach { result ->
       ScanResultCard(
        result,
        showUninstall = result.packageName != null && result.packageName != context.packageName &&
         result.verdict in listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS),
        showQuarantine = result.sourceUri != null && result.verdict in listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS),
        onUninstall = { packageName ->
         lastUninstallPackage = packageName
         pendingUninstallPackage = packageName
         when (vm.requestUninstall(context, packageName,
          launchDelete = { intent -> deleteLauncher.launch(intent) },
          openAppInfo = { intent -> context.startActivity(intent) })) {
          UninstallResult.Success, UninstallResult.RequiresUserAction -> Unit
          is UninstallResult.BlockedSystemApp -> {
           showUninstallSnackbar(context.getString(R.string.uninstall_protected), null)
           try { context.startActivity(UninstallHandler.buildAppInfoIntent(packageName)) }
           catch (e: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
           catch (e: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
          }
          UninstallResult.NotFound -> { pendingUninstallPackage = null; lastUninstallPackage = null; showUninstallSnackbar(context.getString(R.string.uninstall_not_found), null) }
          UninstallResult.OpenedAppInfo -> showUninstallSnackbar(context.getString(R.string.uninstall_opened_app_info), packageName)
          UninstallResult.HandlerUnavailable -> { pendingUninstallPackage = null; showUninstallSnackbar(context.getString(R.string.uninstall_launch_failed), packageName) }
         }
        },
        showAppInfo = true,
        onAppInfo = { packageName ->
         try { context.startActivity(UninstallHandler.buildAppInfoIntent(packageName)) }
         catch (e: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
         catch (e: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
        },
        onQuarantine = { pendingQuarantine = result }, onTrust = { vm.trustApp(it) }, onRemoveTrust = vm::removeTrust
       )
      }
     }
    }
    if (selectedDestination == "quarantine") {
    Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
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
         val byteSize = runCatching { quarantineManager.displaySize(file) }.getOrDefault(0L)
         Text(pluralStringResource(R.plurals.l10n_bytes, byteSize.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), byteSize),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
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
     SafeMobileSettingsPanel(
      monitoringRunning, enableSentinel, disableSentinel,
      strictMode = strictMode,
      securityAlertsEnabled = securityAlertsEnabled,
      onSecurityAlertsChanged = changeSecurityAlerts,
      onToggleProtection = toggleProtection, onStrictModeChanged = updateStrictMode,
       appTheme = appTheme, onAppThemeChanged = onAppThemeChanged
     )
    }
    if (selectedDestination == "pro") {
     SafeMobileProPaywallScreen(onBack = { selectedDestination = "home" })
    }
    if (selectedDestination == "capabilities") {
     DetectionCapabilitiesScreen(
      hashDatabaseCapability = state.hashDatabaseCapability,
      initialSyncPending = initialHashSyncPending,
       yaraMatchCount = state.results.sumOf { it.riskReport?.yaraResult?.matches?.size ?: 0 },
       yaraMatchedRuleNames = state.results.flatMap { it.riskReport?.yaraResult?.matchedRules.orEmpty() }.distinct(),
      onImportYaraRulesForReview = { pendingYaraPicker.launch(arrayOf("text/plain", "application/octet-stream", "application/x-yara")) }
     )
    }
    Spacer(Modifier.height(8.dp))
   }
   SnackbarHost(hostState = snackbarHostState)
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
      label = { Text(stringResource(destination.second), maxLines = 1, softWrap = false, overflow = TextOverflow.Ellipsis) }
     )
    }
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
  QuarantineDeleteDialog(
   fileName = runCatching { quarantineManager.displayName(file) }.getOrDefault(file.name),
   onDismiss = { pendingDeleteFile = null },
   onConfirm = {
    // Dismiss synchronously before starting asynchronous file/Room work.
    pendingDeleteFile = null
     uiScope.launch { withFrameNanos { }; vm.deleteQuarantinedFile(file) }
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
 pendingGlobalDonationResults.firstOrNull()?.let { detectedThreat ->
  AlertDialog(
   onDismissRequest = { pendingGlobalDonationResults = pendingGlobalDonationResults.drop(1) },
   title = { Text(stringResource(R.string.global_threat_intelligence_title)) },
   text = { Text(stringResource(R.string.global_threat_intelligence_donate_message)) },
   confirmButton = {
    TextButton(onClick = {
     pendingGlobalDonationResults = pendingGlobalDonationResults.drop(1)
     if (GlobalThreatIntelligenceConsent.isEnabled(context)) {
      uiScope.launch { GlobalThreatIntelligenceDonor(context).donateScanResult(detectedThreat) }
     }
    }) { Text(stringResource(R.string.global_threat_intelligence_donate)) }
   },
   dismissButton = {
    TextButton(onClick = { pendingGlobalDonationResults = pendingGlobalDonationResults.drop(1) }) {
     Text(stringResource(R.string.global_threat_intelligence_decline))
    }
   }
  )
 }
 if (showNotificationPermissionPrompt) AlertDialog(
   onDismissRequest = { showNotificationPermissionPrompt = false; pendingAlertEnable = false },
   title = { Text(stringResource(R.string.security_alerts_title)) },
   text = { Text(stringResource(R.string.incident_alerts_explanation)) },
   confirmButton = {
    TextButton(onClick = {
     showNotificationPermissionPrompt = false
     if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
     } else {
      pendingAlertEnable = false
      securityAlertsEnabled = true
      securityPrefs.edit().putBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, true).apply()
     }
    }) { Text(stringResource(R.string.setup_allow_notifications)) }
   },
   dismissButton = {
    TextButton(onClick = {
     showNotificationPermissionPrompt = false
     pendingAlertEnable = false
    }) { Text(stringResource(R.string.setup_notifications_not_now)) }
   }
  )
  if (showStoragePermissionPrompt) AlertDialog(
   onDismissRequest = { showStoragePermissionPrompt = false; pendingSentinelEnable = false; selectedDestination = "home" },
   title = { Text(stringResource(R.string.setup_sentinel_title)) },
   text = { Text(stringResource(R.string.ui_folder_picker_explanation)) },
   confirmButton = {
    TextButton(onClick = {
     showStoragePermissionPrompt = false
     runCatching { storageTreeLauncher.launch(StorageAccessPreferences.pickerIntent(pendingFolderRole)) }
      .onFailure {
       pendingSentinelEnable = false; selectedDestination = "home"
       Toast.makeText(context, R.string.ui_folder_picker_unavailable, Toast.LENGTH_LONG).show()
      }
    }) { Text(stringResource(R.string.setup_allow_storage)) }
   },
   dismissButton = {
    TextButton(onClick = {
     showStoragePermissionPrompt = false
     pendingSentinelEnable = false
     storageAccessGranted = hasSharedStorageAccess(context)
     selectedDestination = "home"
    }) { Text(stringResource(R.string.setup_continue_limited)) }
   }
  )
  if (showPlayProtectDialog) AlertDialog(
  onDismissRequest = { showPlayProtectDialog = false },
  title = { Text(stringResource(R.string.ui_play_protect_title)) },
  text = { Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
   Text(stringResource(R.string.ui_play_protect_description))
   TextButton(onClick = {
    runCatching {
     val intent = context.packageManager.getLaunchIntentForPackage("com.android.vending")
      ?: throw ActivityNotFoundException()
     context.startActivity(intent)
    }.onFailure { Toast.makeText(context, R.string.ui_google_play_unavailable, Toast.LENGTH_LONG).show() }
   }) { Text(stringResource(R.string.ui_open_google_play)) }
  } },
  confirmButton = { TextButton(onClick = { vm.reportPlayProtect(true); showPlayProtectDialog = false }) { Text(stringResource(R.string.ui_checked_on)) } },
  dismissButton = { Row {
   TextButton(onClick = { vm.reportPlayProtect(false); showPlayProtectDialog = false }) { Text(stringResource(R.string.ui_checked_off)) }
   TextButton(onClick = { showPlayProtectDialog = false }) { Text(stringResource(R.string.ui_not_now)) }
  } }
 )
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
@Composable private fun ScanResultCard(
 result:ScanResult, showUninstall:Boolean, showQuarantine:Boolean, showAppInfo:Boolean,
 onUninstall:(String)->Unit, onAppInfo:(String)->Unit, onQuarantine:()->Unit,
 onTrust:(ScanResult)->Unit = {}, onRemoveTrust:(String)->Unit = {}
) {
 val context=LocalContext.current
 val packageName=result.packageName
 val guard=packageName?.let { SystemPackageGuard.evaluate(context,it) }
 val protectedSystem=guard is PackageGuardResult.BlockedSystemApp
 Column(verticalArrangement=Arrangement.spacedBy(6.dp),modifier=Modifier.fillMaxWidth()) {
  com.vibesync.antivirus.ui.components.ThreatListItem(
   result=result,isProtectedSystemApp=protectedSystem,
   showUninstall=showUninstall && guard is PackageGuardResult.Allowed,
   showQuarantine=showQuarantine,showAppInfo=showAppInfo && protectedSystem,
   onUninstall=onUninstall,onAppInfo=onAppInfo,onQuarantine=onQuarantine,onTrust=onTrust,onRemoveTrust=onRemoveTrust
  )
  result.scanSessionId?.takeIf { it.isNotBlank() }?.let {
   Text(stringResource(R.string.history_session)+": "+it,modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
  result.threatEventId?.takeIf { it.isNotBlank() }?.let {
   Text(stringResource(R.string.threat_event_ray_id,it),modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
  result.mlProbability?.let { p ->
   Text(stringResource(R.string.ml_probability, (p * 100).toInt().coerceIn(0, 100)),
    modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,
    color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
  result.sha256?.let {
   Text(stringResource(R.string.file_hash_label,it.take(24)),modifier=Modifier.padding(horizontal=8.dp),style=MaterialTheme.typography.labelSmall,color=MaterialTheme.colorScheme.onSurfaceVariant)
  }
 }
}

