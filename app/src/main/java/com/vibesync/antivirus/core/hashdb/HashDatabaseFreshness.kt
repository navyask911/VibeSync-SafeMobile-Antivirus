package com.vibesync.antivirus.core.hashdb

import android.content.Context

/** Publication time of the GitHub release whose database was successfully signature verified. */
object HashDatabaseFreshness {
    private const val PREFS = "safe_mobile_hashdb_freshness"
    fun recordVerifiedRelease(context: Context, version: Long, publishedAt: Long) {
        require(version > 0 && publishedAt > 0 && publishedAt <= System.currentTimeMillis() + 300_000L)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putLong("version", version).putLong("published_at", publishedAt).apply()
    }
    fun updatedAt(context: Context, activeVersion: Long?): Long? {
        if (activeVersion == null) return null
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        return prefs.getLong("published_at", 0L).takeIf { prefs.getLong("version", -1L) == activeVersion && it > 0L }
    }
}
