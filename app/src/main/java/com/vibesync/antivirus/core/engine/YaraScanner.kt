package com.vibesync.antivirus.core.engine

import java.io.File

enum class YaraScanState { MATCHES, NO_MATCH, DISABLED, NOT_SCANNED }
data class YaraScanResult(val state: YaraScanState, val matchedRules: List<String> = emptyList(), val reason: String? = null)

/** Explicit capability boundary: no scan is claimed unless libyara and rules are shipped. */
class YaraScanner {
    fun scan(file: File): YaraScanResult =
        if (!file.isFile || !file.canRead()) YaraScanResult(YaraScanState.NOT_SCANNED, reason = "Input file is unavailable or unreadable.")
        else YaraScanResult(YaraScanState.DISABLED, reason = DISABLED_REASON)

    companion object {
        const val DISABLED_REASON = "No libyara JNI runtime or curated bundled YARA rules are shipped."
    }
}
