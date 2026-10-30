package com.vibesync.antivirus.core.worker

import android.os.FileObserver
import android.util.AtomicFile
import java.io.File
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map

/** App-private, bounded cache. A failed refresh leaves the last valid snapshot readable offline. */
internal class ThreatIntelligenceStore(filesDir: File) {
    private val directory = File(filesDir, "ml-research-candidates")
    private val file = AtomicFile(File(directory, ThreatIntelligenceStats.FILE_NAME))

    fun read(): ThreatIntelligenceStats? = synchronized(CACHE_LOCK) { try {
        file.openRead().use { input ->
            val bytes = ByteArray(ThreatIntelligenceStats.MAX_BYTES + 1)
            var size = 0
            while (size < bytes.size) {
                val count = input.read(bytes, size, bytes.size - size)
                if (count < 0) break
                if (count == 0) break
                size += count
            }
            ThreatIntelligenceStats.parse(bytes.copyOf(size))
        }
    } catch (_: IOException) {
        null
    } }

    /** The downloaded JSON is saved verbatim only after all four fields validate. */
    fun write(bytes: ByteArray): Boolean {
        if (ThreatIntelligenceStats.parse(bytes) == null) return false
        return synchronized(CACHE_LOCK) {
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("No statistics storage")
        val output = file.startWrite()
        try {
            output.write(bytes)
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        }
        true
        }
    }

    /** No network or polling from Compose; reload on resume and on an atomic cache replacement. */
    @Suppress("DEPRECATION") // String-path FileObserver is available on every supported API (26+).
    fun observe(): Flow<ThreatIntelligenceStats?> = callbackFlow<Unit> {
        if (!directory.isDirectory && !directory.mkdirs()) {
            trySend(Unit)
            close()
            return@callbackFlow
        }
        val observer = object : FileObserver(directory.absolutePath,
            FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO or FileObserver.DELETE) {
            override fun onEvent(event: Int, path: String?) {
                if (path == ThreatIntelligenceStats.FILE_NAME) trySend(Unit)
            }
        }
        observer.startWatching()
        trySend(Unit)
        awaitClose { observer.stopWatching() }
    }.conflate().map { read() }.flowOn(Dispatchers.IO)

    private companion object {
        // AtomicFile requires callers to serialize readers/writers, including separate store instances.
        val CACHE_LOCK = Any()
    }
}
