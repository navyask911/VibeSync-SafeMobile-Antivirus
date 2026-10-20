package com.vibesync.antivirus.presentation
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.vibesync.antivirus.R
import com.vibesync.antivirus.core.engine.ScanResult
import com.vibesync.antivirus.core.engine.ScanVerdict
import com.vibesync.antivirus.data.repository.ThreatRepository
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
 val signatureCount: Int = 0
) {
 val threatCount: Int get() = results.count { it.verdict == ScanVerdict.THREAT }
 val suspiciousCount: Int get() = results.count { it.verdict == ScanVerdict.SUSPICIOUS }
}

class SafeMobileViewModel(private val repository: ThreatRepository) : ViewModel() {
 private val mutableState = MutableStateFlow(SafeMobileUiState())
 val state = mutableState.asStateFlow()
 init { refreshSignatureCount() }

 fun scanInstalled() = runScan { repository.scanInstalledApps() }
 fun scanSelected(uri: Uri) = runScan { listOf(repository.scanUri(uri)) }

 private fun runScan(task: suspend () -> List<ScanResult>) {
  if (mutableState.value.isScanning) return
  viewModelScope.launch {
   mutableState.update { it.copy(isScanning = true, messageResource = null) }
   runCatching { task() }
    .onSuccess { results ->
     mutableState.update { it.copy(isScanning = false, results = results,
      completedScans = it.completedScans + 1, lastScanAt = System.currentTimeMillis(),
      messageResource = R.string.scan_complete) }
     refreshSignatureCount()
    }
    .onFailure {
     mutableState.update { it.copy(isScanning = false, messageResource = R.string.scan_failed) }
    }
  }
 }
 private fun refreshSignatureCount() {
  viewModelScope.launch {
   runCatching { repository.signatureCount() }.onSuccess { count ->
    mutableState.update { it.copy(signatureCount = count) }
   }
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
