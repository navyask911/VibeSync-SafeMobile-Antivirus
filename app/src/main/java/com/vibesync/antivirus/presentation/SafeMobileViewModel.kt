package com.vibesync.antivirus.presentation

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.locale.UiText
import com.vibesync.antivirus.core.locale.UiNumber
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.InstalledAppItem
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.core.hashdb.HashDatabaseCapability
import com.vibesync.antivirus.data.repository.ThreatRepository
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SafeMobileUiState(
    val scanSummary: com.vibesync.antivirus.core.engine.ScanCompletionSummary? = null,
    val securityAssessment: com.vibesync.antivirus.core.security.DeviceSecurityAssessment? = null,
    val isScanning: Boolean = false,
    val results: List<ScanResult> = emptyList(),
    val installedApps: List<InstalledAppItem> = emptyList(),
    val inventoryLoading: Boolean = false,
    val inventoryLoaded: Boolean = false,
    val completedScans: Int = 0,
    val lastScanAt: Long? = null,
    val messageResource: Int? = null,
    val messageText: UiText? = null,
    val signatureCount: Int = 0,
    val processedItems: Int = 0,
    val totalItems: Int = 0,
    val quarantinedFiles: List<File> = emptyList(),
    val activeThreatIndicatorCount: Int = 0,
    val lastThreatFeedSyncAt: Long? = null,
    val threatFeedSyncStatus: String? = null,
    val threatFeedSyncError: String? = null,
    val hashDatabaseCapability: HashDatabaseCapability = HashDatabaseCapability(false, reason = ""),
) {
    val threatCount get() = results.count { it.verdict == ScanVerdict.THREAT }
    val suspiciousCount get() = results.count { it.verdict == ScanVerdict.SUSPICIOUS }
}

class SafeMobileViewModel(private val repository: ThreatRepository) : ViewModel() {
    private val mutableState = MutableStateFlow(SafeMobileUiState())
    val state = mutableState.asStateFlow()
    private var scanJob: Job? = null

    init {
        repository.loadScanSummary()?.let { summary ->
            mutableState.update { it.copy(scanSummary = summary, lastScanAt = summary.completedAt) }
        }
        refreshSecurityScore()
        refreshSignatureCount()
        refreshQuarantine()
        observeThreatFeedState()
        refreshHashDatabaseCapability()
    }

    private fun observeThreatFeedState() {
        viewModelScope.launch {
            repository.observeActiveThreatIndicatorCount().collect { count ->
                mutableState.update { it.copy(activeThreatIndicatorCount = count) }
            }
        }
        viewModelScope.launch {
            repository.observeLastSuccessfulThreatFeedSyncAt().collect { timestamp ->
                mutableState.update { it.copy(lastThreatFeedSyncAt = timestamp) }
            }
        }
        viewModelScope.launch {
            repository.observeLatestThreatFeedSyncState().collect { sync ->
                mutableState.update { it.copy(threatFeedSyncStatus = sync?.status, threatFeedSyncError = sync?.lastError) }
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

    fun requestThreatFeedSync() { repository.requestThreatFeedSync() }

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
                                    riskReport = null, threatEventId = null, trustedByUser = true)
                            else it
                        },
                        messageResource = R.string.trusted_app_saved, messageText = null
                    ) }
                } else mutableState.update { it.copy(messageResource = R.string.trusted_app_denied) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(messageResource = R.string.trusted_app_denied) } }
        }
    }

    fun removeTrust(packageName: String) {
        viewModelScope.launch {
            try {
                repository.removeTrust(packageName)
                // Never leave the former override displayed as a measured clean result.
                mutableState.update { old -> old.copy(results = old.results.map { item ->
                    if (item.packageName == packageName) item.copy(trustedByUser = false,
                        verdict = ScanVerdict.NOT_SCANNED, reasons = emptyList(), reasonTexts = emptyList(), riskReport = null,
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
        runScan { onProgress -> repository.scanInstalledApps(onProgress) }
    }

    fun scanFull() = runScan { onProgress ->
        repository.scanFull(onProgress)
    }

    fun scanSelected(uri: Uri) = runScan { _ ->
        listOf(repository.scanUri(uri))
    }

    fun cancelScan() {
        scanJob?.cancel()
    }

    /** Re-check one package after Android's uninstall confirmation flow returns. */
    fun refreshInstalledPackage(packageName: String) {
        viewModelScope.launch {
            val outcome = runCatching { repository.scanInstalledPackage(packageName) }
            mutableState.update { old ->
                if (outcome.isFailure) {
                    old.copy(messageResource = R.string.scan_failed, messageText = null)
                } else {
                    val refreshed = outcome.getOrNull()
                    val updated = if (refreshed == null) {
                        old.results.filterNot { it.packageName == packageName }
                    } else if (old.results.any { it.packageName == packageName }) {
                        old.results.map { if (it.packageName == packageName) refreshed else it }
                    } else {
                        old.results
                    }
                    old.copy(results = updated)
                }
            }
        }
    }

    fun refreshQuarantine() {
        viewModelScope.launch {
            runCatching { repository.listQuarantinedFiles() }
                .onSuccess { files -> mutableState.update { it.copy(quarantinedFiles = files) } }
        }
    }

    fun quarantineSelectedFile(uri: Uri, expectedSha256: String?) {
        viewModelScope.launch {
            mutableState.update { it.copy(messageResource = null, messageText = null) }
            runCatching { repository.quarantineSelectedFile(uri, expectedSha256) }
                .onSuccess { message ->
                    mutableState.update { it.copy(messageText = message, messageResource = null) }
                    refreshQuarantine()
                }
                .onFailure { mutableState.update { it.copy(messageText = null, messageResource = R.string.quarantine_failed) } }
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

    private fun runScan(task: suspend (suspend (Int, Int) -> Unit) -> List<ScanResult>) {
        if (mutableState.value.isScanning || scanJob?.isActive == true) return
        scanJob = viewModelScope.launch {
            mutableState.update {
                it.copy(
                    isScanning = true,
                    processedItems = 0,
                    totalItems = 0,
                    messageResource = null,
                    messageText = null
                )
            }
            try {
                val signedDefinitionsUsed = repository.currentHashDatabaseCapability()?.enabled == true
                val results = task { processed, total ->
                    mutableState.update { state ->
                        state.copy(
                            processedItems = processed.coerceAtLeast(0),
                            totalItems = total.coerceAtLeast(0)
                        )
                    }
                }.filter { repository.isReviewableResult(it) }.sortedBy { result -> when (result.verdict) {
                    ScanVerdict.THREAT -> 0
                    ScanVerdict.SUSPICIOUS -> 1
                    ScanVerdict.NOT_SCANNED -> 2
                    ScanVerdict.NO_MATCH -> 3
                } }
                val summary = com.vibesync.antivirus.core.engine.ScanCompletionSummary.from(
                    results, mutableState.value.processedItems, System.currentTimeMillis()).copy(signedDefinitionsUsed = signedDefinitionsUsed)
                repository.saveScanSummary(summary)
                mutableState.update { state ->
                    state.copy(
                        scanSummary = summary,
                        isScanning = false,
                        results = results,
                        completedScans = state.completedScans + 1,
                        lastScanAt = System.currentTimeMillis(),
                        messageResource = R.string.scan_complete,
                        messageText = null,
                        processedItems = if (state.totalItems > 0) state.totalItems else state.processedItems
                    )
                }
                refreshSignatureCount()
                refreshSecurityScore()
            } catch (cancelled: CancellationException) {
                mutableState.update {
                    it.copy(
                        isScanning = false,
                        processedItems = 0,
                        totalItems = 0,
                        messageResource = R.string.scan_cancelled,
                        messageText = null
                    )
                }
                throw cancelled
            } catch (_: Exception) {
                mutableState.update {
                    it.copy(
                        isScanning = false,
                        processedItems = 0,
                        totalItems = 0,
                        messageResource = R.string.scan_failed,
                        messageText = null
                    )
                }
            } finally {
                scanJob = null
            }
        }
    }

    private fun refreshSignatureCount() {
        viewModelScope.launch {
            runCatching { repository.signatureCount() }
                .onSuccess { count -> mutableState.update { it.copy(signatureCount = count) } }
        }
    }

    class Factory(private val repository: ThreatRepository) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(SafeMobileViewModel::class.java))
            return SafeMobileViewModel(repository) as T
        }
    }
}

