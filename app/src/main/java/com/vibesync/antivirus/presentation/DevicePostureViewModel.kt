package com.vibesync.antivirus.presentation

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.vibesync.antivirus.core.posture.DevicePostureMonitor
import com.vibesync.antivirus.core.posture.DevicePostureReport
import com.vibesync.antivirus.core.posture.DevicePostureRepository
import com.vibesync.antivirus.core.posture.PostureMonitorStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import android.content.Context

data class DevicePostureUiState(val report: DevicePostureReport? = null, val refreshing: Boolean = false,
    val failed: Boolean = false, val monitor: PostureMonitorStatus? = null)

class DevicePostureViewModel(private val repository: DevicePostureRepository) : ViewModel() {
    private val mutableState = MutableStateFlow(DevicePostureUiState(monitor = repository.status()))
    val state = mutableState.asStateFlow()
    private var refreshJob: Job? = null
    private var lastRefreshAt = 0L

    init { viewModelScope.launch { repository.report.collect { report -> mutableState.update { it.copy(report = report) } } } }

    fun refresh(force: Boolean = true) {
        if (refreshJob?.isActive == true || (!force && System.currentTimeMillis() - lastRefreshAt < 60_000L)) return
        refreshJob = viewModelScope.launch {
            mutableState.update { it.copy(refreshing = true, failed = false) }
            try {
                repository.refresh()
                lastRefreshAt = System.currentTimeMillis()
                mutableState.update { it.copy(refreshing = false, monitor = repository.status()) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(refreshing = false, failed = true) } }
        }
    }

    fun setMonitoring(context: Context, enabled: Boolean) {
        val app = context.applicationContext
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { DevicePostureMonitor.setEnabled(app, enabled) }
                mutableState.update { it.copy(monitor = repository.status()) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { mutableState.update { it.copy(failed = true) } }
        }
    }

    class Factory(private val repository: DevicePostureRepository) : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(DevicePostureViewModel::class.java))
            return DevicePostureViewModel(repository) as T
        }
    }
}
