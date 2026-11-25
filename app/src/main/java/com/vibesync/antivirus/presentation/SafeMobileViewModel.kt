package com.vibesync.antivirus.presentation

import android.net.Uri
import android.content.Context
import android.util.Log
import android.speech.tts.TextToSpeech
import java.util.Locale
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.UiText
import com.vibesync.antivirus.core.locale.UiNumber
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.InstalledAppItem
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.observer.ManualThreatAlertPolicy
import com.vibesync.antivirus.core.worker.ScanForegroundService
import com.vibesync.antivirus.core.worker.ScanForegroundEvents
import com.vibesync.antivirus.core.worker.ThreatIntelligenceStore
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability
import com.vibesync.antivirus.data.repository.ThreatRepository
import com.vibesync.antivirus.core.security.GlobalThreatIntelligenceConsent
import com.vibesync.antivirus.core.security.GlobalThreatIntelligenceDonationScheduler
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.launch

/**
 * Presentation state uses Kotlin values only; PackageManager and Android graphics
 * objects are not retained by this ViewModel or exposed through StateFlow.
 */
data class SafeMobileUiState(
    val scanSummary: com.vibesync.antivirus.core.engine.ScanCompletionSummary? = null,
    val securityAssessment: com.vibesync.antivirus.core.security.DeviceSecurityAssessment? = null,
    val isScanning: Boolean = false,
    val results: List<ScanResult> = emptyList(),
    val installedApps: List<InstalledAppItem> = emptyList(),
    val inventoryLoading: Boolean = false,
    val inventoryLoaded: Boolean = false,
    val completedScans: Int = 0,
    val totalScanSessions: Int = 0,
    val activeScanSessions: Int = 0,
    val manualScanCompletionSequence: Long = 0L,
    val manualThreatAlertSequence: Long = 0L,
    val lastScanAt: Long? = null,
    val messageResource: Int? = null,
    val messageText: UiText? = null,
    val signatureCount: Int = 0,
    val processedItems: Int = 0,
    val totalItems: Int = 0,
    val currentScanFile: String? = null,
    val recentScanFiles: List<String> = emptyList(),
    val quarantinedFiles: List<File> = emptyList(),
    val activeThreatIndicatorCount: Int = 0,
    val lastThreatFeedSyncAt: Long? = null,
    val threatFeedSyncStatus: String? = null,
    val threatFeedSyncError: String? = null,
    val hashDatabaseCapability: HashDatabaseCapability = HashDatabaseCapability(false, reason = ""),
    val threatIntelligence: ThreatIntelligenceUiState = ThreatIntelligenceUiState()
) {
    val threatCount get() = results.count { it.verdict == ScanVerdict.THREAT }
    val suspiciousCount get() = results.count { it.verdict == ScanVerdict.SUSPICIOUS }
}

class SafeMobileViewModel(
    private val repository: ThreatRepository,
    appContext: Context? = null
) : ViewModel() {
    private val appContext = appContext?.applicationContext
    private val threatIntelligenceStore: ThreatIntelligenceStore? by lazy {
        this.appContext?.let { ThreatIntelligenceStore(it.filesDir) }
    }
    private var scoreTts: TextToSpeech? = null
    private var lastAnnouncedProtectionScore: Int? = null
    private val mutableState = MutableStateFlow(SafeMobileUiState())
    val state = mutableState.asStateFlow()
    private val mutableProtectionAdvisorState = MutableStateFlow(
        ProtectionAdvisorState(score = 0, pendingCount = 0, issues = emptyList())
    )
    val protectionAdvisorState = mutableProtectionAdvisorState.asStateFlow()
    private var protectionAdvisorJob: Job? = null
    @Volatile private var failedScanSessionId: String? = null
    private var scanTimeoutJob: Job? = null
    @Volatile private var viewModelScanTimedOut = false
    @Volatile private var isScanRunning = false

    /** Run the CPU-only score rubric off the main thread; UI state is published on Main. */
    fun updateProtectionAdvisor(inputs: ProtectionAdvisorInputs, snoozedIds: Set<String>) {
        protectionAdvisorJob?.cancel()
        protectionAdvisorJob = viewModelScope.launch {
            val calculated = withContext(Dispatchers.Default) {
                ProtectionAdvisorEngine.evaluate(inputs, snoozedIds)
            }
            mutableProtectionAdvisorState.value = calculated
        }
    }

    /** Speak the measured, optimized security configuration only after Voice Alerts are enabled. */
    fun onProtectionScoreChanged(score: Int, voiceAlertsEnabled: Boolean) {
        val previous = lastAnnouncedProtectionScore
        lastAnnouncedProtectionScore = score
        if (score == 100 && previous != 100 && voiceAlertsEnabled) {
            speakOptimizedSecurityConfiguration()
        }
    }

    private fun speakOptimizedSecurityConfiguration() {
        val context = appContext ?: return
        scoreTts?.shutdown()
        scoreTts = TextToSpeech(context) { status ->
            if (status == TextToSpeech.SUCCESS) {
                val engine = scoreTts ?: return@TextToSpeech
                val currentLocale = context.resources.configuration.locales[0]
                val result = engine.setLanguage(currentLocale)
                if (result == TextToSpeech.LANG_MISSING_DATA ||
                    result == TextToSpeech.LANG_NOT_SUPPORTED
                ) {
                    engine.setLanguage(Locale.US)
                }
                val textToSpeak = context.getString(R.string.security_score_100_voice)
                engine.speak(textToSpeak, TextToSpeech.QUEUE_FLUSH, null, "100_score_alert")
            }
        }
    }

    override fun onCleared() {
        scanTimeoutJob?.cancel()
        scanTimeoutJob = null
        isScanRunning = false
        scoreTts?.stop()
        scoreTts?.shutdown()
        scoreTts = null
        super.onCleared()
    }

    init {
        repository.loadScanSummary()?.let { summary ->
            mutableState.update { it.copy(scanSummary = summary, lastScanAt = summary.completedAt) }
        }
        refreshSecurityScore()
        refreshSignatureCount()
        refreshQuarantine()
        observeThreatFeedState()
        observeThreatIntelligenceStats()
        refreshThreatIntelligenceStats()
        observeScanSessionCounts()
        observeLatestCompletedScanAt()
        observeScanProgress()
        observeScanCompletionEvents()
        restoreLatestScanResults()
        refreshScanHistory()
        refreshHashDatabaseCapability()
    }

    private fun observeScanSessionCounts() {
        viewModelScope.launch {
            repository.observeScanSessionCounts().collect { counts ->
                mutableState.update {
                    it.copy(
                        completedScans = counts.completed,
                        totalScanSessions = counts.total,
                        activeScanSessions = counts.inProgress
                    )
                }
            }
        }
    }

    private fun observeLatestCompletedScanAt() {
        viewModelScope.launch {
            repository.observeLatestCompletedScanAt().collect { timestamp ->
                if (timestamp != null && timestamp > 0L &&
                    timestamp > (mutableState.value.lastScanAt ?: 0L)
                ) {
                    val latestResults = try {
                        repository.latestCompletedScanResults()
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        null
                    }
                    val latestSummary = repository.loadScanSummary()
                    mutableState.update { current ->
                        if (timestamp > (current.lastScanAt ?: 0L)) {
                            current.copy(
                                lastScanAt = timestamp,
                                scanSummary = latestSummary ?: current.scanSummary,
                                results = latestResults ?: current.results
                            )
                        } else current
                    }
                    // A scheduled worker may have completed while this process was backgrounded.
                    refreshThreatIntelligenceStats()
                }
            }
        }
    }

    /** Re-read preferences and Room when the app returns to the foreground. */
    fun refreshScanHistory() {
        viewModelScope.launch {
            val storedSummary = repository.loadScanSummary()
            val latestRoomTimestamp = runCatching { repository.latestCompletedScanAt() }.getOrNull()
            mutableState.update { current ->
                val latestTimestamp = listOfNotNull(
                    current.lastScanAt,
                    storedSummary?.completedAt,
                    latestRoomTimestamp
                ).maxOrNull()
                current.copy(
                    scanSummary = storedSummary ?: current.scanSummary,
                    lastScanAt = latestTimestamp
                )
            }
        }
    }

    private fun observeThreatFeedState() {
        viewModelScope.launch {
            repository.observeThreatFeedSnapshot().collect { snapshot ->
                mutableState.update { current ->
                    current.copy(
                        activeThreatIndicatorCount = snapshot.activeIndicatorCount,
                        lastThreatFeedSyncAt = snapshot.lastSuccessfulSyncAt,
                        threatFeedSyncStatus = snapshot.latestSyncState?.status,
                        threatFeedSyncError = snapshot.latestSyncState?.lastError,
                        threatIntelligence = current.threatIntelligence.withFeedSnapshot(snapshot)
                    )
                }
            }
        }
    }

    private fun observeThreatIntelligenceStats() {
        val store = threatIntelligenceStore ?: return
        viewModelScope.launch {
            store.observe().collect { stats ->
                mutableState.update { current ->
                    current.copy(threatIntelligence = current.threatIntelligence.withReleaseStats(stats))
                }
            }
        }
    }

    /** Reload the last verified upstream cache and the Room snapshot without starting network work. */
    fun refreshThreatIntelligenceStats() {
        viewModelScope.launch {
            mutableState.update {
                it.copy(threatIntelligence = it.threatIntelligence.copy(isRefreshing = true))
            }
            try {
                val store = threatIntelligenceStore
                val stats = if (store == null) null else withContext(Dispatchers.IO) { store.read() }
                val snapshot = repository.loadThreatFeedSnapshot()
                mutableState.update { current ->
                    val releaseState = if (store != null) {
                        current.threatIntelligence.withReleaseStats(stats)
                    } else {
                        current.threatIntelligence.copy(isRefreshing = false)
                    }
                    val combined = releaseState.withFeedSnapshot(snapshot)
                    current.copy(
                        threatIntelligence = combined,
                        activeThreatIndicatorCount = snapshot.activeIndicatorCount,
                        lastThreatFeedSyncAt = snapshot.lastSuccessfulSyncAt,
                        threatFeedSyncStatus = snapshot.latestSyncState?.status,
                        threatFeedSyncError = snapshot.latestSyncState?.lastError
                    )
                }
            } catch (cancelled: CancellationException) {
                mutableState.update {
                    it.copy(threatIntelligence = it.threatIntelligence.copy(isRefreshing = false))
                }
                throw cancelled
            } catch (_: Exception) {
                mutableState.update {
                    it.copy(threatIntelligence = it.threatIntelligence.copy(isRefreshing = false))
                }
            }
        }
    }


    fun refreshSecurityScore() {
        viewModelScope.launch {
            runCatching { repository.securityAssessment() }.onSuccess { assessment ->
                mutableState.update { it.copy(securityAssessment = assessment, hashDatabaseCapability = repository.currentHashDatabaseCapability() ?: it.hashDatabaseCapability) }
            }
        }
    }
    fun reportPlayProtect(enabled: Boolean) { repository.reportPlayProtect(enabled); refreshSecurityScore() }

    fun refreshHashDatabaseCapability() {
        viewModelScope.launch {
            val capability = try { repository.hashDatabaseCapability() }
            catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) { HashDatabaseCapability(false, reason = "") }
            mutableState.update { it.copy(hashDatabaseCapability = capability) }; refreshSecurityScore()
        }
    }

    fun importSignedHashDatabase(uri: Uri) {
        viewModelScope.launch {
            try {
                val capability = repository.importSignedHashDatabase(uri)
                mutableState.update { it.copy(hashDatabaseCapability = capability, messageResource = null,
                    messageText = UiText(R.string.signed_import_success, listOf(capability.version?.let { UiNumber(it) } ?: "—", UiText(R.plurals.l10n_indicators, listOf(capability.indicatorCount), capability.indicatorCount)))) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) {
                refreshHashDatabaseCapability()
                mutableState.update { it.copy(messageResource = R.string.signed_import_failed,
                    messageText = null) }
            }
        }
    }

    fun importPendingYaraRule(uri: Uri) {
        viewModelScope.launch {
            try {
                val message = repository.importPendingYaraRule(uri)
                mutableState.update { it.copy(messageResource = null, messageText = message) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Exception) {
                mutableState.update { it.copy(messageResource = R.string.rule_import_failed,
                    messageText = null) }
            }
        }
    }

    fun requestHashDatabaseSync() = repository.requestHashDatabaseSync()

    fun requestThreatFeedSync() {
        repository.requestThreatFeedSync()
        refreshThreatIntelligenceStats()
    }

    /** Queue a confirmed threat hash after master opt-in or explicit one-sample consent. */
    fun contributeThreatHash(
        context: Context,
        result: ScanResult,
        oneTimeConsent: Boolean = false
    ): Boolean {
        if (result.verdict != ScanVerdict.THREAT) return false
        if (!oneTimeConsent && !GlobalThreatIntelligenceConsent.isEnabled(context)) return false
        return if (oneTimeConsent) {
            GlobalThreatIntelligenceDonationScheduler.enqueueOnce(context, result)
        } else {
            GlobalThreatIntelligenceDonationScheduler.enqueue(context, result)
        }
    }

    fun uninstallGuard(context: android.content.Context, packageName: String): PackageGuardResult =
        SystemPackageGuard.evaluate(context.applicationContext, packageName)

    fun requestUninstall(
        context: android.content.Context,
        packageName: String,
        launchDelete: (android.content.Intent) -> Unit,
        openAppInfo: (android.content.Intent) -> Unit
    ): UninstallResult = when (val guard = uninstallGuard(context, packageName)) {
        is PackageGuardResult.BlockedSystemApp -> UninstallResult.BlockedSystemApp(guard.reason)
        PackageGuardResult.NotFound -> UninstallResult.NotFound
        PackageGuardResult.Allowed -> UninstallHandler.request(context.applicationContext, packageName, launchDelete, openAppInfo)
    }


    fun refreshInstalledInventory() {
        viewModelScope.launch {
            mutableState.update { it.copy(inventoryLoading = true) }
            try {
                val inventory = withContext(Dispatchers.IO) { repository.installedAppInventory() }
                mutableState.update { it.copy(installedApps = inventory, inventoryLoading = false, inventoryLoaded = true) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                mutableState.update { it.copy(inventoryLoading = false, inventoryLoaded = false, messageResource = R.string.apps_inventory_load_failed) }
            }
        }
    }

    fun trustApp(result: ScanResult) {
        viewModelScope.launch {
            try {
                if (repository.trustApp(result)) {
                    com.vibesync.antivirus.core.observer.SecurityAlertNotifier.stopIncidentAudio()
                    mutableState.update { state -> state.copy(
                        results = state.results.map {
                            if (it.packageName == result.packageName)
                                it.copy(verdict = ScanVerdict.NO_MATCH, riskScore = 0f, reasons = emptyList(), reasonTexts = emptyList(),
                                    riskReport = null, mlProbability = null, threatEventId = null, trustedByUser = true)
                            else it
                        },
                        messageResource = R.string.trusted_app_saved, messageText = null
                    ) }
                } else mutableState.update { it.copy(messageResource = R.string.trusted_app_denied) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(messageResource = R.string.trusted_app_denied) } }
        }
    }

    fun trustPackageName(packageName: String) {
        viewModelScope.launch {
            try {
                if (repository.trustPackageName(packageName)) {
                    mutableState.update { old -> old.copy(messageResource = R.string.trusted_app_saved,
                        results = old.results.map { item ->
                            if (item.packageName == packageName) item.copy(
                                verdict = ScanVerdict.NO_MATCH, riskScore = 0f, reasons = emptyList(),
                                reasonTexts = emptyList(), riskReport = null, mlProbability = null,
                                threatEventId = null, trustedByUser = true
                            ) else item
                        })
                    }
                } else mutableState.update { it.copy(messageResource = R.string.trusted_app_denied) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(messageResource = R.string.trusted_app_denied) } }
        }
    }

    fun trustFileHash(result: ScanResult) = trustFileHash(result.sha256)

    fun trustFileHash(sha256Value: String?) {
        val sha256 = sha256Value?.lowercase()?.takeIf { it.matches(Regex("^[0-9a-f]{64}$")) }
        if (sha256 == null) {
            mutableState.update { it.copy(messageResource = R.string.trusted_file_invalid) }
            return
        }
        viewModelScope.launch {
            try {
                if (repository.trustFileHash(sha256)) {
                    mutableState.update { old -> old.copy(
                        messageResource = R.string.trusted_file_saved,
                        results = old.results.map { item ->
                            if (item.sha256?.equals(sha256, ignoreCase = true) == true) item.copy(
                                verdict = ScanVerdict.NO_MATCH, riskScore = 0f, reasons = emptyList(),
                                reasonTexts = emptyList(), riskReport = null, mlProbability = null,
                                threatEventId = null, trustedByUser = true
                            ) else item
                        }
                    ) }
                } else mutableState.update { it.copy(messageResource = R.string.trusted_file_invalid) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(messageResource = R.string.trusted_file_invalid) } }
        }
    }

    fun removeTrust(packageName: String) {
        viewModelScope.launch {
            try {
                repository.removeTrust(packageName)
                // Never leave the former override displayed as a measured clean result.
                mutableState.update { old -> old.copy(results = old.results.map { item ->
                    if (item.packageName == packageName) item.copy(trustedByUser = false,
                        verdict = ScanVerdict.NOT_SCANNED, reasons = emptyList(), reasonTexts = emptyList(), riskReport = null, mlProbability = null,
                        threatEventId = null) else item
                }, messageResource = R.string.trusted_app_removed, messageText = null) }
                refreshInstalledPackage(packageName)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(messageResource = R.string.trusted_app_remove_failed) } }
        }
    }

    fun refreshTrustOverrides() {
        viewModelScope.launch {
            val names = mutableState.value.results.filter { it.trustedByUser }.mapNotNull { it.packageName }.distinct()
            for (name in names) {
                try {
                    if (!repository.isTrusted(name)) {
                        mutableState.update { old -> old.copy(results = old.results.map { item ->
                            if (item.packageName == name && item.trustedByUser)
                                item.copy(trustedByUser = false, verdict = ScanVerdict.NOT_SCANNED, reasons = emptyList(), reasonTexts = emptyList()) else item
                        }) }
                        refreshInstalledPackage(name)
                    }
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { /* Keep the last displayed state if storage is temporarily unavailable. */ }
            }
        }
    }

    fun scanInstalled() {
        refreshInstalledInventory()
        startBackgroundScan(ScanForegroundService.OP_INSTALLED_APPS, manualScan = true)
    }
    fun scanFull(manualScan: Boolean = true) {
        startBackgroundScan(ScanForegroundService.OP_FULL_DEVICE, manualScan = manualScan)
    }
    fun scanSelected(uri: Uri) {
        startBackgroundScan(ScanForegroundService.OP_SELECTED_FILE, uri.toString(), manualScan = true)
    }
    fun scanInstalledPackageNow(packageName: String) {
        startBackgroundScan(ScanForegroundService.OP_INSTALLED_PACKAGE, packageName = packageName, manualScan = true)
    }
    fun scanFolderTree(uri: Uri) {
        startBackgroundScan(ScanForegroundService.OP_SELECTED_FOLDER, uri.toString(), manualScan = true)
    }
    fun cancelScan() { appContext?.let(ScanForegroundService::stop) }

    private fun startBackgroundScan(operation: String, sourceUri: String? = null,
        packageName: String? = null, manualScan: Boolean) {
        if (isScanRunning) {
            Log.w("ScanDebug", "Ignoring scan request because another scan is already running.")
            return
        }
        isScanRunning = true
        val context = appContext ?: run {
            isScanRunning = false
            mutableState.update { it.copy(isScanning = false, messageResource = R.string.scan_failed) }
            return
        }
        failedScanSessionId = null
        viewModelScanTimedOut = false
        scanTimeoutJob?.cancel()
        mutableState.update { it.copy(isScanning = true, processedItems = 0, totalItems = 0,
            currentScanFile = null, recentScanFiles = emptyList(), messageResource = null, messageText = null) }

        // The service owns the scan work; this ViewModel watchdog waits for its terminal event.
        // Subscribe before starting the service so a very fast scan cannot beat the observer.
        scanTimeoutJob = viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                // This outer deadline also covers foreground-service/session setup, so the
                // UI cannot remain indefinitely in "Preparing scan queue" before item progress begins.
                withTimeout(300_000L) {
                    merge(
                        ScanForegroundEvents.completed.map { Unit },
                        ScanForegroundEvents.cancelled,
                        ScanForegroundEvents.failed.map { Unit }
                    ).first()
                }
            } catch (timeout: TimeoutCancellationException) {
                viewModelScanTimedOut = true
                isScanRunning = false
                Log.e("ScanDebug", "Scan did not complete within 300000 ms.", timeout)
                ScanForegroundService.stop(context)
                mutableState.update { it.copy(isScanning = false, currentScanFile = null,
                    messageResource = R.string.scan_failed, messageText = null) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                Log.e("ScanDebug", "Could not monitor scan completion.", error)
                isScanRunning = false
                ScanForegroundService.stop(context)
                mutableState.update { it.copy(isScanning = false, currentScanFile = null,
                    messageResource = R.string.scan_failed, messageText = null) }
            }
        }

        val startFailure = runCatching {
            ScanForegroundService.start(context, operation, manualScan, sourceUri, packageName)
        }.exceptionOrNull()
        if (startFailure != null) {
            scanTimeoutJob?.cancel()
            scanTimeoutJob = null
            isScanRunning = false
            Log.e("ScanDebug", "Could not start the foreground scan service.", startFailure)
            mutableState.update { it.copy(isScanning = false, messageResource = R.string.scan_failed, messageText = null) }
        }
    }

    private fun observeScanProgress() {
        viewModelScope.launch {
            repository.observeLatestScanState().collect { scan ->
                if (scan != null) mutableState.update { state ->
                    val failed = scan.sessionId == failedScanSessionId
                    val path = if (scan.isComplete || failed) null else scan.currentItemPath
                    val recent = path?.takeIf { it != state.currentScanFile }?.let { (state.recentScanFiles + it).takeLast(8) } ?: state.recentScanFiles
                    state.copy(isScanning = !scan.isComplete && !failed, processedItems = scan.scannedItems,
                        totalItems = scan.totalItems, currentScanFile = path, recentScanFiles = recent,
                        messageResource = if (failed) R.string.scan_failed else state.messageResource,
                        messageText = if (failed) null else state.messageText)
                }
            }
        }
    }

    private fun observeScanCompletionEvents() {
        viewModelScope.launch {
            ScanForegroundEvents.completed.collect { event ->
                val alert = ManualThreatAlertPolicy.shouldAlert(event.manualScan,
                    event.results.any { it.verdict == ScanVerdict.THREAT })
                isScanRunning = false
                mutableState.update { state -> state.copy(scanSummary = event.summary, isScanning = false,
                    processedItems = maxOf(state.processedItems, state.totalItems), currentScanFile = null,
                    results = event.results,
                    manualScanCompletionSequence = state.manualScanCompletionSequence + if (event.manualScan) 1L else 0L,
                    manualThreatAlertSequence = state.manualThreatAlertSequence + if (alert) 1L else 0L,
                    lastScanAt = event.summary.completedAt,
                    messageResource = if (event.summary.skippedFiles > 0) null else R.string.scan_complete,
                    messageText = if (event.summary.skippedFiles > 0)
                        UiText(R.string.scan_complete_skipped, listOf(UiNumber(event.summary.skippedFiles))) else null) }
                refreshSignatureCount()
                refreshSecurityScore()
                refreshThreatIntelligenceStats()
            }
        }
        viewModelScope.launch {
            ScanForegroundEvents.cancelled.collect {
                isScanRunning = false
                failedScanSessionId = null
                val timedOut = viewModelScanTimedOut
                viewModelScanTimedOut = false
                mutableState.update { it.copy(isScanning = false, currentScanFile = null,
                    messageResource = if (timedOut) R.string.scan_failed else R.string.scan_cancelled,
                    messageText = null) }
            }
        }
        viewModelScope.launch {
            ScanForegroundEvents.failed.collect { event ->
                isScanRunning = false
                failedScanSessionId = event.sessionId
                mutableState.update { it.copy(isScanning = false, currentScanFile = null,
                    messageResource = R.string.scan_failed, messageText = null) }
            }
        }
    }

    private fun restoreLatestScanResults() {
        viewModelScope.launch {
            runCatching { repository.latestCompletedScanResults() }.onSuccess { results ->
                if (results.isNotEmpty()) mutableState.update { state -> if (state.results.isEmpty()) state.copy(results = results) else state }
            }
        }
    }

    /** Re-check one package after Android's uninstall confirmation flow returns. */
    fun refreshInstalledPackage(packageName: String) {
        startBackgroundScan(ScanForegroundService.OP_INSTALLED_PACKAGE, packageName = packageName, manualScan = true)
    }

    fun refreshQuarantine() {
        viewModelScope.launch {
            runCatching { repository.listQuarantinedFiles() }
                .onSuccess { files -> mutableState.update { it.copy(quarantinedFiles = files) } }
        }
    }

    fun quarantineSelectedFile(uri: Uri, expectedSha256: String?, onOriginalRetained: () -> Unit = {}) {
        viewModelScope.launch {
            mutableState.update { it.copy(messageResource = null, messageText = null) }
            try {
                val outcome = repository.quarantineSelectedFile(uri, expectedSha256)
                val message = if (outcome.originalRemoved) {
                    UiText(R.string.quarantine_success_removed, listOf(outcome.privateCopy.name))
                } else {
                    UiText(R.string.quarantine_success_copy_only, listOf(outcome.privateCopy.name))
                }
                mutableState.update { it.copy(messageText = message, messageResource = null) }
                refreshQuarantine()
                if (!outcome.originalRemoved) onOriginalRetained()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                mutableState.update { it.copy(messageText = null, messageResource = R.string.quarantine_failed) }
            }
        }
    }

    fun restoreQuarantinedFile(file: File, destinationUri: Uri) {
        viewModelScope.launch {
            mutableState.update { it.copy(messageResource = null, messageText = null) }
            runCatching { repository.restoreQuarantinedFile(file, destinationUri) }
                .onSuccess { message -> mutableState.update { it.copy(messageText = message, messageResource = null) } }
                .onFailure { mutableState.update { it.copy(messageText = null, messageResource = R.string.quarantine_restore_failed) } }
        }
    }

    /**
     * File and Room work runs on IO. UI state is only mutated after returning to Main.
     */
    fun deleteQuarantinedFile(file: File) {
        viewModelScope.launch {
            mutableState.update { it.copy(messageResource = null, messageText = null) }
            try {
                // Never block the UI thread with encrypted-file deletion.
                val message = withContext(Dispatchers.IO) {
                    repository.deleteQuarantinedFile(file)
                }
                mutableState.update { it.copy(messageText = message, messageResource = null) }
                refreshQuarantine()
            } catch (cancelled: CancellationException) {
                // Do not transform lifecycle cancellation into a deletion error.
                throw cancelled
            } catch (_: Exception) {
                mutableState.update {
                    it.copy(messageText = null, messageResource = R.string.quarantine_delete_failed)
                }
                refreshQuarantine()
            }
        }
    }

fun importOfflineDefinitions(uri: Uri) {
        if (mutableState.value.isScanning) return
        viewModelScope.launch {
            mutableState.update { it.copy(messageResource = null, messageText = null) }
            runCatching { repository.importOfflineDefinitions(uri) }
                .onSuccess { message ->
                    mutableState.update { it.copy(messageText = message, messageResource = null) }
                    refreshSignatureCount()
                }
                .onFailure { mutableState.update { it.copy(messageText = null, messageResource = R.string.import_failed) } }
        }
    }

    private fun refreshSignatureCount() {
        viewModelScope.launch {
            runCatching { repository.signatureCount() }
                .onSuccess { count -> mutableState.update { it.copy(signatureCount = count) } }
        }
    }

    class Factory(
        private val repository: ThreatRepository,
        private val appContext: Context? = null
    ) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(SafeMobileViewModel::class.java))
            return SafeMobileViewModel(repository, appContext) as T
        }
    }
}

