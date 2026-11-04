package com.vibesync.antivirus.core.engine.hash

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.Locale

/**
 * Loads the bundled, line-oriented hash signature format:
 *
 *     <hex-digest>:<display-name>
 *
 * The parser deliberately returns only normalized digests. Display labels from
 * external signature sources are not treated as trusted classification metadata.
 */
class SignatureDatabaseParser {

    suspend fun parseDatabase(context: Context, fileName: String): List<String> =
        withContext(Dispatchers.IO) {
            context.applicationContext.assets.open(fileName)
                .bufferedReader(Charsets.UTF_8)
                .useLines { lines ->
                    lines.mapNotNull { raw ->
                        val hash = raw.substringBefore(':').trim().lowercase(Locale.ROOT)
                        hash.takeIf(HASH_PATTERN::matches)
                    }.distinct().toList()
                }
        }

    private companion object {
        val HASH_PATTERN = Regex("(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})")
    }
}
