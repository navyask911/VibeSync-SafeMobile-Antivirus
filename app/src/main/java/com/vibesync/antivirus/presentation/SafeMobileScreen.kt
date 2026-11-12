package com.vibesync.antivirus.presentation
import androidx.compose.animation.AnimatedVisibility
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
import android.os.PowerManager
import android.provider.Settings
import android.provider.DocumentsContract
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.vibesync.antivirus.core.observer.NotificationDeepLink
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.compose.foundation.BorderStroke
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
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.FolderOpen
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.WorkspacePremium
import androidx.compose.material.icons.outlined.MoreVert
import androidx.compose.material.icons.outlined.Settings as SettingsIcon
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import com.vibesync.antivirus.ui.components.CyberCard as Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.window.DialogProperties
import android.widget.Toast
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.ads.AdMobManager
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.connectivity.ConnectivityMonitor
import com.vibesync.antivirus.core.worker.HashDatabaseSyncScheduler
import com.vibesync.antivirus.core.posture.DevicePostureMonitor
import com.vibesync.antivirus.core.observer.StorageSentinelService
import com.vibesync.antivirus.core.observer.StorageAccessPreferences
import com.vibesync.antivirus.core.observer.FullScreenAlertAccess
import com.vibesync.antivirus.core.observer.SecurityAlertNotifier
import com.vibesync.antivirus.core.worker.OverlayRiskReviewManager
import com.vibesync.antivirus.core.security.DeviceOwnerManager
import com.vibesync.antivirus.core.security.DeviceAdminManager
import com.vibesync.antivirus.core.observer.InstallSentinelService
import com.vibesync.antivirus.core.observer.SecurityVoiceAlert
import com.vibesync.antivirus.core.observer.SecurityIncidentSiren
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.DetectionSource
import com.vibesync.antivirus.core.quarantine.LocalQuarantineManager
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.security.GlobalThreatIntelligenceConsent
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.ui.components.EmptyState
import com.vibesync.antivirus.ui.components.SecurityStatusCard
import com.vibesync.antivirus.ui.components.SectionHeader
import com.vibesync.antivirus.ui.components.StatusChip
import com.vibesync.antivirus.ui.components.StatusKind
import java.io.File
import java.text.DateFormat
import java.util.Date
import kotlin.math.roundToInt
import kotlinx.coroutines.launch
@Composable fun SafeMobileTheme(
 theme: com.vibesync.antivirus.ui.theme.AppTheme = com.vibesync.antivirus.ui.theme.AppTheme.DARK_SLATE,
 content: @Composable () -> Unit
) { com.vibesync.antivirus.ui.theme.SafeMobileMaterialTheme(theme = theme, content = content) }
@Composable fun SafeMobileScreen(
 repository:ThreatRepository,
  batteryStatusEpoch: Int = 0,
  appTheme: com.vibesync.antivirus.ui.theme.AppTheme = com.vibesync.antivirus.ui.theme.AppTheme.DARK_SLATE,
  onAppThemeChanged: (com.vibesync.antivirus.ui.theme.AppTheme) -> Unit = {},
 sharedText:String? = null,
 onSharedTextConsumed:() -> Unit = {},
 openQuarantine:Boolean = false,
 onOpenQuarantineConsumed:() -> Unit = {},
 openDevicePosture:Boolean = false,
 onOpenDevicePostureConsumed:() -> Unit = {},
 notificationDeepLink: NotificationDeepLink? = null,
 onNotificationDeepLinkConsumed: () -> Unit = {}
) {
 val context=LocalContext.current
 val safeMobileApp=context.applicationContext as SafeMobileApp
 val adMobManager = remember(safeMobileApp) { safeMobileApp.adMobManager }
 val adMobState by adMobManager.state.collectAsStateWithLifecycle()
 var fullScreenAlertsGranted by remember(context) { mutableStateOf(FullScreenAlertAccess.isGranted(context)) }
 val powerManager = remember(context) { context.getSystemService(Context.POWER_SERVICE) as? PowerManager }
 var batteryUnrestricted by remember(context) {
  mutableStateOf(powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true)
 }
 val activity=context as? Activity
 val vm:SafeMobileViewModel=viewModel(factory=SafeMobileViewModel.Factory(repository, context.applicationContext))
 val state by vm.state.collectAsStateWithLifecycle()
 val installSentinelRunning by com.vibesync.antivirus.core.observer.InstallSentinelService.running.collectAsStateWithLifecycle()
 val postureVm:DevicePostureViewModel=viewModel(factory=DevicePostureViewModel.Factory(safeMobileApp.devicePostureRepository))
 val postureState by postureVm.state.collectAsStateWithLifecycle()
 val initialHashSyncPending by androidx.compose.runtime.produceState(initialValue = false, context) {
  HashDatabaseSyncScheduler.initialSyncPending(context).collect { value = it }
 }
 val auditEntries by repository.observeRecentAudits().collectAsStateWithLifecycle(initialValue = emptyList())
 val securityIncidents by repository.observeRecentSecurityIncidents().collectAsStateWithLifecycle(initialValue = emptyList())
 val ownerManager = remember(context) { DeviceOwnerManager(context) }
 val deviceAdminManager = remember(context) { DeviceAdminManager(context) }
 var adminActive by remember(context) { mutableStateOf(deviceAdminManager.isAdminActive()) }
 var showAdminPermissionDisclosure by rememberSaveable { mutableStateOf(false) }
 var showV17ProtectionSetupSheet by rememberSaveable { mutableStateOf(false) }
 var selectedDestination by rememberSaveable { mutableStateOf("home") }
 var isSubscriptionExpanded by rememberSaveable { mutableStateOf(false) }
 var settingsSubRoute by rememberSaveable { mutableStateOf(SettingsSubRoute.ROOT) }
 val tabNavController = rememberNavController()
 val currentBackStackEntry by tabNavController.currentBackStackEntryAsState()
 val currentDestination = currentBackStackEntry?.destination
 val currentRoute = currentDestination?.route
 val activeTopTab = when {
  currentDestination?.hierarchy?.any { it.route == "tools" } == true -> "tools"
  currentDestination?.hierarchy?.any { it.route == "scan" } == true -> "scan"
  currentDestination?.hierarchy?.any { it.route == "settings" } == true -> "settings"
  currentRoute == "detail/{parentTab}/{screen}" -> currentBackStackEntry?.arguments?.getString("parentTab") ?: "dashboard"
  currentDestination?.hierarchy?.any { it.route == "dashboard" } == true -> "dashboard"
  else -> "dashboard"
 }
 fun navigateToDestination(destination: String, parentTabOverride: String? = null) {
  val rootRoute = when (destination) {
   "home" -> "dashboard"
   "scan" -> "scan"
   "tools" -> "tools"
   "settings" -> "settings"
   else -> null
  }
  if (rootRoute != null) {
   if (currentRoute != rootRoute) {
    tabNavController.navigate(rootRoute) {
     popUpTo(tabNavController.graph.findStartDestination().id) { saveState = true }
     launchSingleTop = true
     restoreState = true
    }
   }
   selectedDestination = destination
  } else {
   val parentTab = parentTabOverride ?: if (destination == "pro") "settings" else
    (currentBackStackEntry?.arguments?.getString("parentTab")
    ?: when (currentRoute) {
     "tools" -> "tools"
     "scan" -> "scan"
     "settings" -> "settings"
     else -> "dashboard"
    })
   tabNavController.navigate("detail/$parentTab/$destination") { launchSingleTop = true }
   selectedDestination = destination
  }
 }
 val openProSafely: () -> Unit = {
  try {
   if (tabNavController.currentDestination == null) Toast.makeText(context, R.string.pro_navigation_unavailable, Toast.LENGTH_LONG).show()
   else navigateToDestination("pro")
  } catch (_: Exception) { Toast.makeText(context, R.string.pro_navigation_unavailable, Toast.LENGTH_LONG).show() }
 }
 val openExternalLink: (String) -> Unit = { url ->
  runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
   .onFailure { Toast.makeText(context, R.string.about_link_unavailable, Toast.LENGTH_LONG).show() }
 }
 LaunchedEffect(currentRoute, currentBackStackEntry?.arguments?.getString("screen")) {
  selectedDestination = when (currentRoute) {
   "dashboard" -> "home"
   "scan" -> "scan"
   "tools" -> "tools"
   "settings" -> "settings"
   "detail/{parentTab}/{screen}" -> currentBackStackEntry?.arguments?.getString("screen") ?: "home"
   else -> "home"
  }
 }
 val contentScrollState = rememberScrollState()
 var folderUris by remember(context) { mutableStateOf(StorageAccessPreferences.accessibleTreeUris(context)) }
 val customFolderUris by StorageAccessPreferences.observeCustomTreeUris(context).collectAsStateWithLifecycle(initialValue = emptyList())
 var pendingFolderRole by remember { mutableStateOf(StorageAccessPreferences.DOWNLOADS) }
 var showPlayProtectDialog by remember { mutableStateOf(false) }
 LaunchedEffect(selectedDestination) { contentScrollState.scrollTo(0) }
 LaunchedEffect(state.scanSummary?.completedAt) {
  if (state.scanSummary != null && selectedDestination == "home") contentScrollState.animateScrollTo(0)
 }
 val onboardingPrefs = remember(context) { context.getSharedPreferences(OnboardingPrefs.NAME, Context.MODE_PRIVATE) }


 var onboardingComplete by remember(context) { mutableStateOf(
  onboardingPrefs.getBoolean(OnboardingPrefs.SECURITY_SETUP_V166_COMPLETED, false)
 ) }
 var storageAccessGranted by remember(context) { mutableStateOf(StorageAccessPreferences.hasAccess(context)) }
 var notificationsGranted by remember(context) { mutableStateOf(hasNotificationAccess(context)) }
 var sentinelOptIn by remember(context) { mutableStateOf(onboardingPrefs.getBoolean(OnboardingPrefs.SENTINEL_OPT_IN, isStorageSentinelRunning(context))) }
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
  state.isScanning -> Icons.Outlined.Security
  state.threatCount > 0 || state.suspiciousCount > 0 || state.results.any { it.verdict == ScanVerdict.NOT_SCANNED } -> Icons.Outlined.Warning
  state.lastScanAt == null || state.results.isEmpty() -> Icons.Outlined.Security
  else -> Icons.Outlined.CheckCircle
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
 var monitoringRunning by remember(context) { mutableStateOf(isStorageSentinelRunning(context) && StorageAccessPreferences.hasAccess(context)) }
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
 var voiceAlertsEnabled by remember(context) { mutableStateOf(securityPrefs.getBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, false)) }
 var installSentinelEnabled by remember(context) { mutableStateOf(InstallSentinelService.enabled(context)) }
 var globalDefenseEnabled by remember(context) { mutableStateOf(GlobalThreatIntelligenceConsent.isEnabled(context)) }
 LaunchedEffect(batteryUnrestricted, adminActive, storageAccessGranted) {
  securityPrefs.edit()
   .putBoolean("guard_battery_optimization", batteryUnrestricted)
   .putBoolean("guard_device_admin", adminActive)
   
   .putBoolean("guard_saf_directory_watch", storageAccessGranted)
   .apply()
 }
 val advisorStore = remember(context) { ProtectionAdvisorStore(context) }
 val snoozedAdvisorIds by advisorStore.snoozedIssueIds.collectAsStateWithLifecycle(initialValue = emptySet())
 val folderSentinelConfigured = StorageAccessPreferences.hasRole(context, StorageAccessPreferences.DOWNLOADS) ||
  StorageAccessPreferences.hasRole(context, StorageAccessPreferences.WHATSAPP) || customFolderUris.isNotEmpty()
 val databaseUpdatedAt = com.vibesync.antivirus.core.hashdb.HashDatabaseFreshness.updatedAt(context, state.hashDatabaseCapability.version)
 val advisorInputs = remember(
  state.completedScans, state.scanSummary, state.threatCount, folderSentinelConfigured,
  postureState.report?.highRiskAppCount, notificationsGranted, securityAlertsEnabled,
  batteryUnrestricted, fullScreenAlertsGranted, databaseUpdatedAt, installSentinelEnabled,
  state.securityAssessment?.signals?.playProtectEnabled,
  state.securityAssessment?.signals?.usbDebuggingEnabled, voiceAlertsEnabled, adminActive
 ) {
  ProtectionAdvisorInputs(
   totalScans = maxOf(state.completedScans, if (state.scanSummary != null) 1 else 0),
   threatsDetected = state.scanSummary?.threats ?: state.threatCount,
   folderSentinelConfigured = folderSentinelConfigured,
   highRiskPostureCount = postureState.report?.highRiskAppCount,
   notificationsEnabled = notificationsGranted && securityAlertsEnabled,
   batteryUnrestricted = batteryUnrestricted,
   fullScreenIntentEnabled = fullScreenAlertsGranted,
   databaseUpdatedAt = databaseUpdatedAt,
   installSentinelEnabled = installSentinelEnabled,
   playProtectEnabled = state.securityAssessment?.signals?.playProtectEnabled,
   usbDebuggingEnabled = state.securityAssessment?.signals?.usbDebuggingEnabled,
   voiceAlertsEnabled = voiceAlertsEnabled,
   deviceAdminActive = adminActive
  )
 }
 val advisorState by vm.protectionAdvisorState.collectAsStateWithLifecycle()
 LaunchedEffect(advisorState.score, voiceAlertsEnabled) {
  vm.onProtectionScoreChanged(advisorState.score, voiceAlertsEnabled)
 }
 LaunchedEffect(advisorInputs, snoozedAdvisorIds) {
  vm.updateProtectionAdvisor(advisorInputs, snoozedAdvisorIds)
 }
 val snackbarHostState = remember { SnackbarHostState() }
 val uiScope = rememberCoroutineScope()
 var lastHandledManualScanSequence by remember { mutableStateOf(state.manualScanCompletionSequence) }
 var lastHandledManualThreatAlertSequence by remember { mutableStateOf(state.manualThreatAlertSequence) }
 LaunchedEffect(privacyAccepted, activity) {
  if (privacyAccepted && activity != null) adMobManager.refresh(activity)
 }
 LaunchedEffect(selectedDestination, privacyAccepted) {
  if (selectedDestination == "home" && privacyAccepted && activity != null)
   adMobManager.refresh(activity)
 }
 DisposableEffect(lifecycleOwner, privacyAccepted, activity) {
  val observer = LifecycleEventObserver { _, event ->
   if (event == Lifecycle.Event.ON_RESUME && privacyAccepted && activity != null) {
    uiScope.launch { adMobManager.refresh(activity) }
   }
  }
  lifecycleOwner.lifecycle.addObserver(observer)
  onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
 }
 LaunchedEffect(state.manualScanCompletionSequence) {
  val completed = state.manualScanCompletionSequence
  if (completed > lastHandledManualScanSequence) {
   lastHandledManualScanSequence = completed
   if (activity != null) adMobManager.showInterstitialAfterManualScan(
    activity = activity,
    manualScanCompleted = true,
    hasConfirmedThreats = state.threatCount > 0
   )
  }
 }
 LaunchedEffect(state.manualThreatAlertSequence) {
  val completed = state.manualThreatAlertSequence
  if (completed > lastHandledManualThreatAlertSequence) {
   lastHandledManualThreatAlertSequence = completed
   val threat = state.results.firstOrNull { it.verdict == ScanVerdict.THREAT }
   if (threat != null) {
    val eventId = "manual-threat-scan-$completed-" + java.util.UUID.randomUUID()
    SecurityAlertNotifier.notifyManualScanThreat(context, eventId)
   }
  }
 }
 var pendingGlobalDonationResults by remember { mutableStateOf<List<ScanResult>>(emptyList()) }
 val promptedGlobalDonationEvents = remember { mutableSetOf<String>() }
 val hasEligibleDonationResult = state.results.any { result ->
  result.verdict == ScanVerdict.THREAT &&
   result.sha256?.matches(Regex("[0-9a-f]{64}")) == true &&
   (result.sourceLocalPath != null || result.sourceUri != null || result.packageName != null) &&
   result.threatEventId?.let { it !in promptedGlobalDonationEvents } == true
 }
 LaunchedEffect(state.results, globalDefenseEnabled, selectedDestination) {
  if (selectedDestination !in setOf("home", "scan", "apps")) return@LaunchedEffect
  val additions = state.results.filter { result ->
   result.verdict == ScanVerdict.THREAT &&
    result.sha256?.matches(Regex("[0-9a-f]{64}")) == true &&
    (result.sourceLocalPath != null || result.sourceUri != null || result.packageName != null) &&
    result.threatEventId?.let { it !in promptedGlobalDonationEvents } == true
  }
  additions.forEach { it.threatEventId?.let(promptedGlobalDonationEvents::add) }
  if (additions.isNotEmpty()) {
   if (GlobalThreatIntelligenceConsent.isEnabled(context)) {
    additions.forEach { vm.contributeThreatHash(context, it) }

   } else {
    pendingGlobalDonationResults = pendingGlobalDonationResults + additions
   }
  }
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
 var pendingNotificationDetails by remember { mutableStateOf<NotificationDeepLink?>(null) }
 var notificationDeleteTarget by remember { mutableStateOf<NotificationDeepLink?>(null) }
 LaunchedEffect(notificationDeepLink) {
  notificationDeepLink?.let { item ->
   pendingNotificationDetails = item
   navigateToDestination("scan")
   onNotificationDeepLinkConsumed()
  }
 }
 var pendingRestoreFile by remember { mutableStateOf<File?>(null) }
 var pendingDeleteFile by remember { mutableStateOf<File?>(null) }
 var showRestoreWarning by remember { mutableStateOf(false) }
 val quarantineManager = remember(context) { LocalQuarantineManager(context) }
 val apkPicker=rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri:Uri? ->
  uri?.let { selectedUri ->
   // A queued WorkManager contribution may run after the picker Activity and screen close.
   runCatching {
    context.contentResolver.takePersistableUriPermission(
     selectedUri, Intent.FLAG_GRANT_READ_URI_PERMISSION
    )
   }.onFailure { error ->
    android.util.Log.w("Donation", "Could not persist source document access for deferred donation", error)
   }
   vm.scanSelected(selectedUri)
  }
 }
 val deepFolderPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
  uri?.let { treeUri ->
   runCatching { context.contentResolver.takePersistableUriPermission(treeUri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
    .onFailure { error -> android.util.Log.w("SafeMobileDeepScan", "Could not persist selected tree grant; scan uses the current grant", error) }
   navigateToDestination("scan")
   vm.scanFolderTree(treeUri)
  }
 }
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
   navigateToDestination("home")
   return@folderResult
  }
  if (StorageAccessPreferences.isStorageRoot(uri)) {
   Toast.makeText(context, R.string.ui_storage_root_blocked, Toast.LENGTH_LONG).show()
   pendingSentinelEnable = false
   navigateToDestination("home")
   return@folderResult
  }
  val role = pendingFolderRole
  val grantFlags = result.data?.flags ?: Intent.FLAG_GRANT_READ_URI_PERMISSION
  val accessibleCustomFolderUris = customFolderUris.filter { it in StorageAccessPreferences.accessibleTreeUris(context) }
  val customLimitReached = role == StorageAccessPreferences.CUSTOM &&
   accessibleCustomFolderUris.size >= StorageAccessPreferences.MAX_CUSTOM_FOLDERS && uri !in accessibleCustomFolderUris
  uiScope.launch {
   val granted = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
    runCatching {
     if (role == StorageAccessPreferences.CUSTOM) StorageAccessPreferences.persistCustomFolder(context, uri, grantFlags)
     else StorageAccessPreferences.persistSelectedFolder(context, uri, role, grantFlags)
    }.getOrDefault(false)
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
    Handler(Looper.getMainLooper()).postDelayed({ monitoringRunning = isStorageSentinelRunning(context) && StorageAccessPreferences.hasAccess(context) }, 900L)
   } else {
    Toast.makeText(context,
     if (customLimitReached) R.string.ui_sentinel_folder_limit else R.string.ui_folder_access_not_granted,
     Toast.LENGTH_LONG).show()
    navigateToDestination("home")
   }
  }
 }
 val requestStorage: () -> Unit = { navigateToDestination("sentinel") }
 val enableSentinel: () -> Unit = {
  if (!StorageAccessPreferences.hasAccess(context)) requestStorage()
  else runCatching { context.startForegroundService(Intent(context, StorageSentinelService::class.java)) }
   .onSuccess {
    securityPrefs.edit().putBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, true).apply()
    sentinelDesired = true
    sentinelOptIn = true
    Handler(Looper.getMainLooper()).postDelayed({
     storageAccessGranted = StorageAccessPreferences.hasAccess(context)
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
 val toggleBatteryGuard: (Boolean) -> Unit = { enabled ->
  val intent = if (enabled) {
   Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}"))
  } else Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
  runCatching { context.startActivity(intent) }.onFailure {
   runCatching { context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
    .onFailure { Toast.makeText(context, R.string.battery_review_unavailable, Toast.LENGTH_LONG).show() }
  }
 }
 val toggleAdminGuard: (Boolean) -> Unit = { enabled ->
  if (enabled) {
   if (!deviceAdminManager.isAdminActive()) {
    runCatching { deviceAdminManager.requestAdminPermission() }
     .onFailure { Toast.makeText(context, R.string.device_admin_activation_failed, Toast.LENGTH_LONG).show() }
   }
  } else {
   runCatching { deviceAdminManager.removeAdmin() }
    .onFailure { Toast.makeText(context, R.string.device_admin_explanation, Toast.LENGTH_LONG).show() }
  }
 }
 val requestDeviceLock: () -> Unit = {
  runCatching { deviceAdminManager.lockDeviceNow() }
   .onFailure {
    Toast.makeText(context, R.string.device_admin_lock_failed, Toast.LENGTH_LONG).show()
   }
 }
 val toggleSafGuard: (Boolean) -> Unit = { enabled ->
  if (enabled) {
   requestPrivacyAcknowledgement {
    pendingFolderRole = StorageAccessPreferences.DOWNLOADS
    pendingSentinelEnable = true
    runCatching { storageTreeLauncher.launch(StorageAccessPreferences.pickerIntent(StorageAccessPreferences.DOWNLOADS)) }
     .onFailure {
      pendingSentinelEnable = false
      Toast.makeText(context, R.string.ui_folder_picker_unavailable, Toast.LENGTH_LONG).show()
     }
   }
  } else {
   uiScope.launch {
    runCatching { kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
     StorageAccessPreferences.revokeAllFolders(context)
    } }.onFailure { android.util.Log.w("SafeMobileSAF", "Could not revoke every selected folder grant", it) }
    folderUris = StorageAccessPreferences.accessibleTreeUris(context)
    storageAccessGranted = folderUris.isNotEmpty()
    disableSentinel()
   }
  }
 }
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
  onboardingPrefs.edit()
   .putBoolean(OnboardingPrefs.COMPLETED, true)
   .putBoolean(OnboardingPrefs.SECURITY_SETUP_V166_COMPLETED, true)
   .putInt(OnboardingPrefs.STEP, 4)
   .apply()
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
    adminActive = deviceAdminManager.isAdminActive()
    voiceAlertsEnabled = securityPrefs.getBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, false)
    installSentinelEnabled = InstallSentinelService.enabled(context)
    batteryUnrestricted = powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
    folderUris = StorageAccessPreferences.accessibleTreeUris(context)
    storageAccessGranted = folderUris.isNotEmpty()
    vm.refreshSecurityScore()
    if (privacyAccepted) postureVm.refreshAuditSilently()
    ownerManager.refreshState()
    sentinelDesired = securityPrefs.getBoolean(SafeMobileApp.KEY_DOWNLOAD_SENTINEL_ENABLED, false)
    sentinelOptIn = sentinelDesired
    strictMode = securityPrefs.getBoolean(SafeMobileApp.KEY_STRICT_MODE, false)
    securityAlertsEnabled = securityPrefs.getBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, false)
    globalDefenseEnabled = GlobalThreatIntelligenceConsent.isEnabled(context)
    monitoringRunning = isStorageSentinelRunning(context) && storageAccessGranted
    if (!storageAccessGranted && isStorageSentinelRunning(context)) {
     context.stopService(Intent(context, StorageSentinelService::class.java))
     monitoringRunning = false
    } else if (sentinelDesired && storageAccessGranted && !monitoringRunning) {
     runCatching { context.startForegroundService(Intent(context, StorageSentinelService::class.java)) }
      .onFailure { Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show() }
     Handler(Looper.getMainLooper()).postDelayed({
      monitoringRunning = isStorageSentinelRunning(context) && StorageAccessPreferences.hasAccess(context)
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
   vm.scanFull(manualScan = false)
  }
 }
 LaunchedEffect(initialHashSyncPending) {
  if (!initialHashSyncPending) { vm.refreshHashDatabaseCapability(); vm.refreshSecurityScore() }
 }
 LaunchedEffect(lifecycleOwner, privacyAccepted) {
  lifecycleOwner.lifecycle.repeatOnLifecycle(Lifecycle.State.STARTED) {
   while (true) {
    fullScreenAlertsGranted = FullScreenAlertAccess.isGranted(context)
    batteryUnrestricted = powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
    folderUris = StorageAccessPreferences.accessibleTreeUris(context)
    storageAccessGranted = folderUris.isNotEmpty()
    monitoringRunning = isStorageSentinelRunning(context) && storageAccessGranted
    vm.refreshSecurityScore()
    if (privacyAccepted) postureVm.refresh(force = false)
    kotlinx.coroutines.delay(30_000L)
   }
  }
 }
 LaunchedEffect(sharedText) { if (!sharedText.isNullOrBlank()) navigateToDestination("phishing") }
 LaunchedEffect(openQuarantine) {
  if (openQuarantine) {
   navigateToDestination("quarantine")
   onOpenQuarantineConsumed()
  }
 }
 LaunchedEffect(openDevicePosture) {
  if (openDevicePosture) {
   navigateToDestination("posture")
   if (privacyAccepted) postureVm.refresh()
   onOpenDevicePostureConsumed()
  }
 }
 LaunchedEffect(state.messageResource) {
  if (state.messageResource == R.string.quarantine_delete_failed) {
   Toast.makeText(context, R.string.quarantine_delete_failed, Toast.LENGTH_LONG).show()
  }
 }
 Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
  if (!onboardingComplete) {
   Box(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing)) {
    SecuritySetupScreen(
     initialSyncPending = initialHashSyncPending,
     notificationsGranted = notificationsGranted,
     globalDefenseEnabled = globalDefenseEnabled,
     folderAccessGranted = storageAccessGranted,
     batteryOptimizationExempt = batteryUnrestricted,
     onRequestNotifications = {
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !hasNotificationAccess(context)) {
       pendingAlertEnable = true
       notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
      } else {
       notificationsGranted = hasNotificationAccess(context)
       securityAlertsEnabled = true
       securityPrefs.edit().putBoolean(SafeMobileApp.KEY_SECURITY_ALERTS_ENABLED, true).apply()
      }
     },
     onToggleGlobalDefense = { enabled ->
      GlobalThreatIntelligenceConsent.setEnabled(context, enabled)
      globalDefenseEnabled = enabled
     },
     onChooseFolder = {
      pendingFolderRole = StorageAccessPreferences.DOWNLOADS
      pendingSentinelEnable = true
      runCatching { storageTreeLauncher.launch(StorageAccessPreferences.pickerIntent(StorageAccessPreferences.DOWNLOADS)) }
       .onFailure {
        pendingSentinelEnable = false
        Toast.makeText(context, R.string.ui_folder_picker_unavailable, Toast.LENGTH_LONG).show()
       }
     },
     onRequestBatteryOptimization = {
      batteryUnrestricted = powerManager?.isIgnoringBatteryOptimizations(context.packageName) == true
      if (!batteryUnrestricted) {
       val batteryIntent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}"))
       runCatching { context.startActivity(batteryIntent) }
        .onFailure {
         runCatching { context.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)) }
          .onFailure { Toast.makeText(context, R.string.battery_review_unavailable, Toast.LENGTH_LONG).show() }
        }
      }
     },
     onFinish = finishOnboarding,
     onSkipSetup = finishOnboarding
    )
   }
  } else {
   Scaffold(
    modifier = Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing),
    topBar = {
     V17TopBar(
      appTheme = appTheme, isPro = adMobState.isPro,
      showBack = selectedDestination !in setOf("home", "scan", "tools", "settings"),
      onThemeToggle = {
       onAppThemeChanged(when (appTheme) {
        com.vibesync.antivirus.ui.theme.AppTheme.LIGHT -> com.vibesync.antivirus.ui.theme.AppTheme.DARK_SLATE
        com.vibesync.antivirus.ui.theme.AppTheme.DARK_SLATE -> com.vibesync.antivirus.ui.theme.AppTheme.OLED
        com.vibesync.antivirus.ui.theme.AppTheme.OLED -> com.vibesync.antivirus.ui.theme.AppTheme.LIGHT
        com.vibesync.antivirus.ui.theme.AppTheme.MIDNIGHT -> com.vibesync.antivirus.ui.theme.AppTheme.OLED
       })
      },
      onProClick = openProSafely,
      onBack = { if (!tabNavController.popBackStack()) navigateToDestination("home") }
     )
    },
    bottomBar = {
     Column {
      if (adMobState.adsReady && !adMobState.isPro) AdMobBanner(adMobManager)
      if (selectedDestination in setOf("home", "scan", "tools", "settings")) {
       V17BottomNavigationBar(
        selectedTab = if (activeTopTab == "dashboard") "home" else activeTopTab,
        isDark = appTheme != com.vibesync.antivirus.ui.theme.AppTheme.LIGHT,
        onSelect = { navigateToDestination(it) }
       )
      }
     }
    },
    snackbarHost = { SnackbarHost(hostState = snackbarHostState) },
    containerColor = MaterialTheme.colorScheme.background
   ) { scaffoldPadding ->
    Column(Modifier.fillMaxSize().padding(scaffoldPadding)) {
   val navScreenContent: @Composable () -> Unit = {
       Box(Modifier.fillMaxSize()) {
        when (selectedDestination) {
         "home" -> V17ShieldScreen(
          isDark = appTheme != com.vibesync.antivirus.ui.theme.AppTheme.LIGHT,
          securityScore = advisorState.score,
          isPro = adMobState.isPro,
          activeGuards = listOf(batteryUnrestricted, adminActive, storageAccessGranted).count { it },
          liveSentinelActive = installSentinelRunning,
          posturePassed = postureState.report?.highRiskAppCount?.let { (8 - it.coerceIn(0, 8)).coerceIn(0, 8) },
          quarantinedFilesCount = state.quarantinedFiles.size,
          onOpenSetup = { showV17ProtectionSetupSheet = true },
          onOpenLiveSentinel = { navigateToDestination("sources") },
          onOpenPosture = { navigateToDestination("posture"); if (privacyAccepted) postureVm.refreshAuditSilently() },
          onOpenDetection = { navigateToDestination("capabilities") },
          onOpenThreatDb = { navigateToDestination("quarantine") },
          onOpenPrivacy = { navigateToDestination("privacy") },
          onOpenSettings = { navigateToDestination("settings") }
         )
         "privacy" -> PrivacyDashboardScreen()
         "about" -> AboutUsScreen(
          onOpenWebsite = { openExternalLink("https://vibesyncro.com/") },
          onOpenStore = openExternalLink
         )
         "scan" -> V17ScanLabScreen(
          isDark = appTheme != com.vibesync.antivirus.ui.theme.AppTheme.LIGHT,
          state = state,
          repository = repository,
          onStartQuickScan = { requestPrivacyAcknowledgement { vm.scanInstalled() } },
          onStartDeepScan = { requestPrivacyAcknowledgement {
           deepFolderPicker.launch(StorageAccessPreferences.deepScanInitialUri())
          } },
          onCancelScan = vm::cancelScan,
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
             catch (_: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
             catch (_: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
            }
            UninstallResult.NotFound -> {
             pendingUninstallPackage = null
             lastUninstallPackage = null
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
           catch (_: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
           catch (_: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
          },
          onQuarantine = { pendingQuarantine = it },
          onTrust = vm::trustApp,
          onRemoveTrust = vm::removeTrust
         )
         "tools" -> V17ToolsHubScreen(
          isDark = appTheme != com.vibesync.antivirus.ui.theme.AppTheme.LIGHT,
          onOpen = { destination ->
           navigateToDestination(destination)
           if (destination == "posture" && privacyAccepted) postureVm.refreshAuditSilently()
          }
         )
         "settings" -> V17ConsoleSettingsScreen(
          isDark = appTheme != com.vibesync.antivirus.ui.theme.AppTheme.LIGHT,
          appTheme = appTheme,
          onAppThemeChanged = onAppThemeChanged,
          sirenEnabled = securityAlertsEnabled,
          onSirenChanged = changeSecurityAlerts,
          onTestSiren = {
           try { SecurityIncidentSiren.start(context) { Toast.makeText(context, R.string.test_siren_failed, Toast.LENGTH_LONG).show() } }
           catch (_: Exception) { Toast.makeText(context, R.string.test_siren_failed, Toast.LENGTH_LONG).show() }
          },
          onTestVoice = {
           try { SecurityVoiceAlert.speakForTest(context) { Toast.makeText(context, R.string.test_voice_failed, Toast.LENGTH_LONG).show() } }
           catch (_: Exception) { Toast.makeText(context, R.string.test_voice_failed, Toast.LENGTH_LONG).show() }
          },
          voiceEnabled = voiceAlertsEnabled,
          onVoiceChanged = { enabled ->
           voiceAlertsEnabled = enabled
           securityPrefs.edit().putBoolean(SafeMobileApp.KEY_VOICE_ALERTS_ENABLED, enabled).apply()
           if (!enabled) SecurityVoiceAlert.stop()
          },
          installSentinelEnabled = installSentinelEnabled,
          installSentinelRunning = installSentinelRunning,
          onInstallSentinelChanged = { enabled ->
           if (enabled) {
            requestPrivacyAcknowledgement {
             securityPrefs.edit().putBoolean(SafeMobileApp.KEY_INSTALL_SENTINEL_ENABLED, true).apply()
             installSentinelEnabled = true
             if (!InstallSentinelService.startFromVisibleUi(context))
              Toast.makeText(context, R.string.monitor_start_failed, Toast.LENGTH_LONG).show()
            }
           } else {
            installSentinelEnabled = false
            InstallSentinelService.stop(context)
           }
          },
          globalIntelEnabled = globalDefenseEnabled,
          onGlobalIntelChanged = { enabled ->
           requestPrivacyAcknowledgement {
            GlobalThreatIntelligenceConsent.setEnabled(context, enabled)
            globalDefenseEnabled = enabled
           }
          },
          batteryActive = batteryUnrestricted,
          adminActive = adminActive,
          safActive = storageAccessGranted,
          onBatteryToggle = toggleBatteryGuard,
          onAdminToggle = toggleAdminGuard,
          onLockDeviceNow = requestDeviceLock,
          onSafToggle = toggleSafGuard,
          onImportYara = { pendingYaraPicker.launch(arrayOf("text/plain", "application/octet-stream", "application/x-yara")) },
          onThreatFeedSync = { requestPrivacyAcknowledgement { vm.requestThreatFeedSync() } },
          onBenchmarks = { navigateToDestination("scan") },
          onOpenPro = openProSafely,
          onOpenPrivacy = { navigateToDestination("privacy") },
          onOpenAbout = { navigateToDestination("about") }
         )
         else -> Column(
          Modifier.fillMaxSize().verticalScroll(contentScrollState)
           .padding(horizontal = 16.dp, vertical = 16.dp),
          verticalArrangement = Arrangement.spacedBy(14.dp)
         ) {
          if (selectedDestination == "advisor") {
           SecurityAdvisorScreen(
            state = advisorState,
            onOpenIssue = { issue ->
             if (issue.destination == "settings") {
              settingsSubRoute = when (issue.id) {
               "notifications_on", "fullscreen_alert", "voice_alert_tts" -> SettingsSubRoute.NOTIFICATIONS
               else -> SettingsSubRoute.SECURITY
              }
              navigateToDestination("settings")
             } else navigateToDestination(issue.destination)
            },
            onSnooze = { issueId -> uiScope.launch { advisorStore.setSnoozed(issueId, true) } },
            onRestore = { issueId -> uiScope.launch { advisorStore.setSnoozed(issueId, false) } }
           )
          }
        if (privacyAccepted && !notificationsGranted && Build.VERSION.SDK_INT >= 33) {
           Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
             Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
          onResults = { navigateToDestination(if (state.results.isEmpty()) "history" else "scan") },
          onCancel = vm::cancelScan)
        }
        if (selectedDestination == "home") {
         DevicePostureDashboardCard(postureState, onOpen = {
          navigateToDestination("posture")
          if (privacyAccepted) postureVm.refresh()
         })
         LimitedProtectionBanner(
          downloads = folderUris.isNotEmpty() && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.DOWNLOADS),
          whatsapp = folderUris.isNotEmpty() && StorageAccessPreferences.hasRole(context, StorageAccessPreferences.WHATSAPP),
          running = monitoringRunning, onSetup = { navigateToDestination("sentinel") })
         SecurityDashboard(state.securityAssessment,
          onCheckPlayProtect = { requestPrivacyAcknowledgement { showPlayProtectDialog = true } },
          onSync = { vm.requestHashDatabaseSync() })
         HomeSecurityMetrics(
          summary = state.scanSummary,
          hashDbPublishedAt = com.vibesync.antivirus.core.hashdb.HashDatabaseFreshness.updatedAt(context, state.hashDatabaseCapability.version)
         )
         if (initialHashSyncPending) {
          Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.primaryContainer),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
           Row(Modifier.padding(16.dp), horizontalArrangement=Arrangement.spacedBy(10.dp), verticalAlignment=Alignment.CenterVertically) {
            CircularProgressIndicator(Modifier.size(18.dp), strokeWidth=2.dp)
            Text(stringResource(R.string.hash_database_initial_syncing), style=MaterialTheme.typography.bodyMedium)
           }
          }
         }
         Button(onClick = { requestPrivacyAcknowledgement { vm.scanFull() } }, enabled = !state.isScanning, modifier = Modifier.fillMaxWidth()) {
          androidx.compose.material3.Icon(Icons.Outlined.Security, contentDescription = null)
          Text(stringResource(R.string.security_scan_now), Modifier.padding(start = 8.dp))
         }
          SectionHeader(title=stringResource(R.string.analytics_recent_activity), actionLabel=stringResource(R.string.nav_history), onAction={ navigateToDestination("history") })
         if (auditEntries.isEmpty()) EmptyState(title=stringResource(R.string.analytics_no_audits),description=stringResource(R.string.analytics_no_audits_body))
         else auditEntries.take(3).forEach { audit ->
          Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surface),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
           Row(Modifier.padding(12.dp),verticalAlignment=Alignment.CenterVertically,horizontalArrangement=Arrangement.spacedBy(10.dp)) {
            androidx.compose.material3.Icon(if(audit.verdict==ScanVerdict.THREAT.name) Icons.Outlined.Warning else Icons.Outlined.History,
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
          ExpandableText(stringResource(R.string.scan_explanation), maxLines = 3)
          Button(onClick={ requestPrivacyAcknowledgement { vm.scanFull() } },enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) {
           if(state.isScanning) CircularProgressIndicator(Modifier.size(18.dp),strokeWidth=2.dp,color=MaterialTheme.colorScheme.onPrimary) else androidx.compose.material3.Icon(Icons.Outlined.Security,contentDescription=null)
           Text(stringResource(if(state.isScanning) R.string.scan_running else R.string.security_scan_now),modifier=Modifier.padding(start=8.dp))
          }
          OutlinedButton(onClick={ requestPrivacyAcknowledgement { apkPicker.launch(arrayOf("*/*")) } },enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) {
           androidx.compose.material3.Icon(Icons.Outlined.FolderOpen,contentDescription=null)
           Text(stringResource(R.string.scan_selected),modifier=Modifier.padding(start=8.dp))
          }
          OutlinedButton(onClick={ requestPrivacyAcknowledgement { showDefinitionImportWarning = true } },enabled=!state.isScanning,modifier=Modifier.fillMaxWidth()) { Text(stringResource(R.string.import_definitions)) }
         }
        }
        }
        if (selectedDestination == "home") CoreStrengthsAccordion { destination -> navigateToDestination(destination) }
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
          customFolders = customFolderUris.filter { it in folderUris },
          onAdd = { role -> requestPrivacyAcknowledgement {
           pendingFolderRole = role; pendingSentinelEnable = true; showStoragePermissionPrompt = true
          } },
          onAddCustom = { requestPrivacyAcknowledgement {
           pendingFolderRole = StorageAccessPreferences.CUSTOM
           pendingSentinelEnable = true
           showStoragePermissionPrompt = true
          } },
          onRemove = { uri -> uiScope.launch {
           kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { StorageAccessPreferences.removeSelectedFolder(context, uri) }
           folderUris = StorageAccessPreferences.accessibleTreeUris(context)
           storageAccessGranted = folderUris.isNotEmpty()
           if (!storageAccessGranted) disableSentinel()
          } },
          onStart = { requestPrivacyAcknowledgement { enableSentinel() } }, onStop = disableSentinel,
          onSkip = { navigateToDestination("home") })
        }
        if (selectedDestination == "guardian") GuardianPanel()
        if (selectedDestination == "posture") DevicePostureScreen(
         state = postureState, alertsAvailable = securityAlertsEnabled && notificationsGranted,
         actionableActionsCount = advisorState.pendingCount,
         onRefresh = { requestPrivacyAcknowledgement { postureVm.refresh() } },
         onMonitoringChanged = { enabled ->
          if (enabled) requestPrivacyAcknowledgement { postureVm.setMonitoring(context, true) }
          else postureVm.setMonitoring(context, false)
         },
         onEnableAlerts = { requestPrivacyAcknowledgement { changeSecurityAlerts(true) } }
        )
        if (selectedDestination == "phishing") PhishingPanel(sharedText, repository) { onSharedTextConsumed() }
        if (selectedDestination == "cleaner") StorageCleanerPanel()
        state.messageResource?.takeUnless { it == R.string.scan_complete && selectedDestination in listOf("home", "scan") }?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) { Text(stringResource(message),Modifier.padding(16.dp),color=MaterialTheme.colorScheme.onSurface,style=MaterialTheme.typography.bodySmall) } }
        state.messageText?.let { message -> Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant)) { Text(message.resolve(context),Modifier.padding(16.dp),color=MaterialTheme.colorScheme.onSurface,style=MaterialTheme.typography.bodySmall,maxLines=3,overflow=TextOverflow.Ellipsis) } }
        if(selectedDestination == "scan" && state.results.isNotEmpty()) {
         ScanResultsScreen(
          results = state.results,
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
          onAppInfo = { packageName ->
           try { context.startActivity(UninstallHandler.buildAppInfoIntent(packageName)) }
           catch (e: ActivityNotFoundException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
           catch (e: SecurityException) { showUninstallSnackbar(context.getString(R.string.uninstall_no_settings), packageName) }
          },
          onQuarantine = { pendingQuarantine = it },
          onTrust = vm::trustApp,
          onRemoveTrust = vm::removeTrust
         )
        }
        if (selectedDestination == "quarantine") {
        Card(colors=CardDefaults.cardColors(containerColor=MaterialTheme.colorScheme.surfaceVariant),shape=RoundedCornerShape(16.dp),modifier=Modifier.fillMaxWidth()) {
         Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
          Text(stringResource(R.string.quarantine_vault_title),style=MaterialTheme.typography.titleMedium,fontWeight=FontWeight.Bold)
          ExpandableText(stringResource(R.string.quarantine_vault_description), maxLines = 3)
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
           appTheme = appTheme, onAppThemeChanged = onAppThemeChanged,
           adPrivacyOptionsRequired = adMobState.privacyOptionsRequired,
           isProForAds = adMobState.isPro,
           onManageFolders = { navigateToDestination("sentinel") },
           onAddCustomFolder = { requestPrivacyAcknowledgement {
            navigateToDestination("sentinel")
            pendingFolderRole = StorageAccessPreferences.CUSTOM
            pendingSentinelEnable = true
            showStoragePermissionPrompt = true
           } },
           onShowAdPrivacyOptions = {
            activity?.let { host -> uiScope.launch { adMobManager.showPrivacyOptions(host) } }
           }
         )
        }
        if (selectedDestination == "pro") {
         SafeMobileProPaywallScreen(
          onBack = { if (!tabNavController.popBackStack()) navigateToDestination("home") },
          onProStatusChanged = { isPro -> if (isPro) adMobManager.disableForPro() }
         )
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
        }
       }
   }
   NavHost(
    navController = tabNavController,
    startDestination = "dashboard",
    modifier = Modifier.weight(1f).fillMaxWidth()
   ) {
    composable("dashboard") { navScreenContent() }
    composable("scan") { navScreenContent() }
    composable("tools") { navScreenContent() }
    composable("settings") { navScreenContent() }
    composable("detail/{parentTab}/{screen}") { navScreenContent() }
   }
   if (showV17ProtectionSetupSheet) {
    V17ProtectionSetupSheet(
     isDark = appTheme != com.vibesync.antivirus.ui.theme.AppTheme.LIGHT,
     batteryActive = batteryUnrestricted,
     adminActive = adminActive,
     safActive = storageAccessGranted,
     onDismiss = { showV17ProtectionSetupSheet = false },
     onBatteryToggle = toggleBatteryGuard,
     onAdminToggle = toggleAdminGuard,
     onSafToggle = toggleSafGuard
    )
   }

   }
  }
 }
 }

 pendingNotificationDetails?.let { item ->
  ThreatDetailsDialog(
   item = item,
   onDismiss = { pendingNotificationDetails = null },
   onScan = {
    pendingNotificationDetails = null
    navigateToDestination("scan")
    val packageName = item.packageName
     ?: item.fileUri?.takeIf { it.startsWith("package:") }?.removePrefix("package:")
    if (!packageName.isNullOrBlank()) {
     requestPrivacyAcknowledgement { vm.scanInstalledPackageNow(packageName) }
    } else {
     val uri = item.fileUri?.let { runCatching { Uri.parse(it) }.getOrNull() }
     if (uri != null) {
      runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
      requestPrivacyAcknowledgement { vm.scanSelected(uri) }
     } else Toast.makeText(context, R.string.notification_details_scan_unavailable, Toast.LENGTH_LONG).show()
    }
   },
   onDelete = {
    val packageName = item.packageName
     ?: item.fileUri?.takeIf { it.startsWith("package:") }?.removePrefix("package:")
    if (!packageName.isNullOrBlank()) {
     pendingNotificationDetails = null
     lastUninstallPackage = packageName
     pendingUninstallPackage = packageName
     when (vm.requestUninstall(context, packageName,
      launchDelete = { intent -> deleteLauncher.launch(intent) },
      openAppInfo = { intent -> context.startActivity(intent) })) {
      UninstallResult.Success, UninstallResult.RequiresUserAction -> Unit
      is UninstallResult.BlockedSystemApp -> showUninstallSnackbar(context.getString(R.string.uninstall_protected), packageName)
      UninstallResult.NotFound -> showUninstallSnackbar(context.getString(R.string.uninstall_not_found), null)
      UninstallResult.OpenedAppInfo -> showUninstallSnackbar(context.getString(R.string.uninstall_opened_app_info), packageName)
      UninstallResult.HandlerUnavailable -> showUninstallSnackbar(context.getString(R.string.uninstall_launch_failed), packageName)
     }
    } else if (!item.fileUri.isNullOrBlank()) {
     notificationDeleteTarget = item
     pendingNotificationDetails = null
    } else Toast.makeText(context, R.string.notification_details_delete_failed, Toast.LENGTH_LONG).show()
   },
   onWhitelist = {
    val packageName = item.packageName
     ?: item.fileUri?.takeIf { it.startsWith("package:") }?.removePrefix("package:")
    if (!packageName.isNullOrBlank()) vm.trustPackageName(packageName)
    else {
     val incidentHash = securityIncidents.firstOrNull { it.eventId == item.logId }?.sha256Hash
     val match = state.results.lastOrNull { result ->
      (item.fileUri != null && result.sourceUri == item.fileUri) ||
       (item.fileName != null && result.displayName.equals(item.fileName, ignoreCase = true)) ||
       (item.filePath != null && result.packageOrPath == item.filePath)
     }
     when {
      !incidentHash.isNullOrBlank() -> vm.trustFileHash(incidentHash)
      match?.sha256?.isNotBlank() == true -> vm.trustFileHash(match)
      else -> Toast.makeText(context, R.string.notification_details_whitelist_scan_first, Toast.LENGTH_LONG).show()
     }
    }
    pendingNotificationDetails = null
   }
  )
 }
 notificationDeleteTarget?.let { item ->
  AlertDialog(
   onDismissRequest = { notificationDeleteTarget = null },
   title = { Text(stringResource(R.string.notification_details_delete_confirm_title)) },
   text = { Text(stringResource(R.string.notification_details_delete_confirm_body)) },
   confirmButton = {
    TextButton(onClick = {
     notificationDeleteTarget = null
     val uri = runCatching { Uri.parse(item.fileUri.orEmpty()) }.getOrNull()
     uiScope.launch {
      val deleted = withContext(Dispatchers.IO) {
       when (uri?.scheme) {
        "file" -> uri.path?.let { File(it).takeIf { file -> file.isFile }?.delete() } == true
        "content" -> runCatching {
         if (DocumentsContract.isDocumentUri(context, uri)) DocumentsContract.deleteDocument(context.contentResolver, uri)
         else context.contentResolver.delete(uri, null, null) > 0
        }.getOrDefault(false)
        else -> false
       }
      }
      Toast.makeText(context,
       if (deleted) R.string.notification_details_deleted else R.string.notification_details_delete_failed,
       Toast.LENGTH_LONG).show()
     }
    }) { Text(stringResource(R.string.notification_details_delete)) }
   },
   dismissButton = { TextButton(onClick = { notificationDeleteTarget = null }) { Text(stringResource(R.string.close)) } }
  )
 }
 if (showAdminPermissionDisclosure) {
  DeviceAdminPermissionDisclosureDialog(
   onConfirm = {
    showAdminPermissionDisclosure = false
    runCatching { deviceAdminManager.requestAdminPermission() }
     .onFailure { Toast.makeText(context, R.string.device_admin_explanation, Toast.LENGTH_LONG).show() }
   },
   onDismiss = { showAdminPermissionDisclosure = false }
  )
 }
 if (showDefinitionImportWarning) AlertDialog(
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
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
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
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
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
   onDismissRequest={ pendingQuarantine = null },
   title={ Text(stringResource(R.string.quarantine_confirm_title)) },
   text={ Text(stringResource(R.string.quarantine_confirm_body)) },
   confirmButton={ TextButton(onClick={
    val uri = runCatching { Uri.parse(flagged.sourceUri) }.getOrNull()
    if (uri != null) vm.quarantineSelectedFile(uri, flagged.sha256) {
     Toast.makeText(context, R.string.quarantine_manual_delete, Toast.LENGTH_LONG).show()
    }
    pendingQuarantine = null
   }) { Text(stringResource(R.string.quarantine_confirm_action)) } },
   dismissButton={ TextButton(onClick={ pendingQuarantine = null }) { Text(stringResource(R.string.close)) } }
  )
 }
 pendingGlobalDonationResults.firstOrNull()?.let { detectedThreat ->
  AlertDialog(
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
   onDismissRequest = { pendingGlobalDonationResults = pendingGlobalDonationResults.drop(1) },
   title = { Text(stringResource(R.string.global_threat_intelligence_title)) },
   text = { Text(stringResource(R.string.global_threat_intelligence_donate_message)) },
   confirmButton = {
    TextButton(onClick = {
     pendingGlobalDonationResults = pendingGlobalDonationResults.drop(1)
     vm.contributeThreatHash(
      context = context,
      result = detectedThreat,
      oneTimeConsent = !GlobalThreatIntelligenceConsent.isEnabled(context)
     )
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
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
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
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
   onDismissRequest = { showStoragePermissionPrompt = false; pendingSentinelEnable = false; navigateToDestination("home") },
   title = { Text(stringResource(R.string.setup_sentinel_title)) },
   text = { Text(stringResource(R.string.ui_folder_picker_explanation)) },
   confirmButton = {
    TextButton(onClick = {
     showStoragePermissionPrompt = false
     runCatching { storageTreeLauncher.launch(StorageAccessPreferences.pickerIntent(pendingFolderRole)) }
      .onFailure {
       pendingSentinelEnable = false; navigateToDestination("home")
       Toast.makeText(context, R.string.ui_folder_picker_unavailable, Toast.LENGTH_LONG).show()
      }
    }) { Text(stringResource(R.string.setup_allow_storage)) }
   },
   dismissButton = {
    TextButton(onClick = {
     showStoragePermissionPrompt = false
     pendingSentinelEnable = false
     storageAccessGranted = StorageAccessPreferences.hasAccess(context)
     navigateToDestination("home")
    }) { Text(stringResource(R.string.setup_continue_limited)) }
   }
  )
  if (showPlayProtectDialog) AlertDialog(
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
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
  properties = DialogProperties(dismissOnClickOutside = true, dismissOnBackPress = true),
  onDismissRequest={ showPrivacyDisclosure=false; pendingSensitiveAction=null },
  title={ Text(stringResource(R.string.privacy_title)) },
  text={ Text(stringResource(R.string.ad_privacy_intro)) },
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
@Composable
internal fun ScanResultsScreen(
 results: List<ScanResult>,
 onUninstall: (String) -> Unit,
 onAppInfo: (String) -> Unit,
 onQuarantine: (ScanResult) -> Unit,
 onTrust: (ScanResult) -> Unit,
 onRemoveTrust: (String) -> Unit
) {
 if (results.isEmpty()) return
 val context = LocalContext.current
 Column(
  verticalArrangement = Arrangement.spacedBy(12.dp),
  modifier = Modifier.fillMaxWidth().padding(top = 4.dp)
 ) {
  Text(stringResource(R.string.latest_results),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Bold)
  val threatTotal = results.count { it.verdict == ScanVerdict.THREAT }
  val reviewTotal = results.count { it.verdict == ScanVerdict.SUSPICIOUS }
  val noMatchTotal = results.count { it.verdict == ScanVerdict.NO_MATCH }
  val notScannedCount = results.count { it.verdict == ScanVerdict.NOT_SCANNED }
  Text(
   listOf(
    pluralStringResource(R.plurals.l10n_threats, threatTotal, threatTotal),
    pluralStringResource(R.plurals.l10n_review, reviewTotal, reviewTotal),
    pluralStringResource(R.plurals.l10n_no_match, noMatchTotal, noMatchTotal),
    pluralStringResource(R.plurals.l10n_unreadable, notScannedCount, notScannedCount)
   ).joinToString(" · "),
   color=MaterialTheme.colorScheme.onSurfaceVariant,
   style=MaterialTheme.typography.bodySmall
  )
  Row(horizontalArrangement=Arrangement.spacedBy(10.dp), modifier=Modifier.fillMaxWidth()) {
   ScanVerdictCountTile(threatTotal, R.drawable.ic_verdict_threat, R.string.verdict_threat, MaterialTheme.colorScheme.error,
    modifier=Modifier.weight(1f))
   ScanVerdictCountTile(reviewTotal, R.drawable.ic_verdict_suspicious, R.string.verdict_suspicious, MaterialTheme.colorScheme.tertiary,
    modifier=Modifier.weight(1f))
  }
  Row(horizontalArrangement=Arrangement.spacedBy(10.dp), modifier=Modifier.fillMaxWidth()) {
   ScanVerdictCountTile(noMatchTotal, R.drawable.ic_verdict_no_match, R.string.verdict_no_match, MaterialTheme.colorScheme.onSurfaceVariant,
    modifier=Modifier.weight(1f))
   ScanVerdictCountTile(notScannedCount, R.drawable.ic_verdict_not_scanned, R.string.verdict_not_scanned, MaterialTheme.colorScheme.onSurfaceVariant,
    modifier=Modifier.weight(1f))
  }
  Text(stringResource(R.string.scan_explanation),
   style=MaterialTheme.typography.bodySmall, color=MaterialTheme.colorScheme.onSurfaceVariant)
  results.take(80).forEach { result ->
   ScanResultCard(
    result,
    showUninstall = result.packageName != null && result.packageName != context.packageName &&
     result.verdict in listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS),
    showQuarantine = result.sourceUri != null &&
     result.verdict in listOf(ScanVerdict.THREAT, ScanVerdict.SUSPICIOUS),
    onUninstall = onUninstall,
    showAppInfo = true,
    onAppInfo = onAppInfo,
    onQuarantine = { onQuarantine(result) },
    onTrust = onTrust,
    onRemoveTrust = onRemoveTrust
   )
  }
 }
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
  if ((result.verdict == ScanVerdict.THREAT || result.verdict == ScanVerdict.SUSPICIOUS) &&
   result.detectionSource != DetectionSource.NONE) {
   val sourceText = if (result.detectionSource == DetectionSource.ENSEMBLE) {
    val confidencePercent = result.confidence.takeIf { it.isFinite() }
     ?.coerceIn(0f, 1f)?.let { (it * 100f).roundToInt() } ?: 0
    stringResource(R.string.scan_detected_by_confidence, result.detectionSource.name, confidencePercent)
   } else {
    stringResource(R.string.scan_detected_by, result.detectionSource.name)
   }
   Text(
    sourceText,
    modifier = Modifier.padding(horizontal = 8.dp),
    style = MaterialTheme.typography.labelSmall,
    color = MaterialTheme.colorScheme.onSurfaceVariant
   )
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



@Composable
private fun ScanVerdictCountTile(
    count: Int,
    iconResource: Int,
    labelResource: Int,
    accent: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant),
        elevation = CardDefaults.cardElevation(defaultElevation = 0.dp)
    ) {
        Column(
            Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                androidx.compose.material3.Icon(
                    painter = painterResource(iconResource),
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(22.dp)
                )
                Text(
                    count.toString(),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = accent
                )
            }
            Text(
                stringResource(labelResource),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
