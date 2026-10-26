package com.vibesync.antivirus.core.observer

/** Main-thread lifecycle for one five-second alarm. A new incident always starts a new session. */
internal class IncidentSirenController(
    private val stopPlayback: () -> Unit,
    private val schedule: (Runnable, Long) -> Unit,
    private val cancel: (Runnable) -> Unit
) {
    private var deadline: Runnable? = null

    fun start(startPlayback: () -> Unit) {
        stop()
        try {
            startPlayback()
        } catch (error: Exception) {
            stop()
            throw error
        }
        val task = object : Runnable {
            override fun run() {
                if (deadline === this) stop()
            }
        }
        deadline = task
        schedule(task, DURATION_MS)
    }

    fun stop() {
        deadline?.let(cancel)
        deadline = null
        stopPlayback()
    }

    companion object { const val DURATION_MS = 5_000L }
}
