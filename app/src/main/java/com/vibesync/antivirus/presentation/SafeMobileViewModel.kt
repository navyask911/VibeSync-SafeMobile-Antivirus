package com.vibesync.antivirus.presentation

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.repository.ThreatRepository
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class SafeMobileUiState(
    val isScanning: Boolean = false,
    val results: List<ScanResult> = emptyList(),
    val completedScans: Int = 0,
    val lastScanAt: Long? = null,
    val messageResource: Int? = null,
    val messageText: String? = null,
    val signatureCount: Int = 0,
    val processedItems: Int = 0,
    val totalItems: Int = 0,
    val quarantinedFiles: List<File> = emptyList()
) {
    val threatCount get() = results.count { it.verdict == ScanVerdict.THREAT }
    val suspiciousCount get() = results.count { it.verdict == ScanVerdict.SUSPICIOUS }
}

class SafeMobileViewModel(private val repository: ThreatRepository) : ViewModel() {
    private val mutableState = MutableStateFlow(SafeMobileUiState())
    val state = mutableState.asStateFlow()
    private var scanJob: Job? = null

    init { refreshSignatureCount(); refreshQuarantine() }

    fun scanInstalled() = runScan { onProgress ->
        repository.scanInstalledApps(onProgress)
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

    fun deleteQuarantinedFile(file: File) {
        viewModelScope.launch {
            mutableState.update { it.copy(messageResource = null, messageText = null) }
            runCatching { repository.deleteQuarantinedFile(file) }
                .onSuccess { message ->
                    mutableState.update { it.copy(messageText = message, messageResource = null) }
                    refreshQuarantine()
                }
                .onFailure { mutableState.update { it.copy(messageText = null, messageResource = R.string.quarantine_delete_failed) } }
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
                val results = task { processed, total ->
                    mutableState.update { state ->
                        state.copy(
                            processedItems = processed.coerceAtLeast(0),
                            totalItems = total.coerceAtLeast(0)
                        )
                    }
                }
                mutableState.update { state ->
                    state.copy(
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
