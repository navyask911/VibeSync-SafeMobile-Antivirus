package com.vibesync.antivirus.data.repository

import com.vibesync.antivirus.data.local.MalwareHashDao
import com.vibesync.antivirus.data.local.MalwareHashEntity
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateDao
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import java.util.Locale
import java.net.URI

/** Indexed local-only lookups. These functions never perform network I/O. */
class ThreatIntelligenceRepository(
    private val malwareHashDao: MalwareHashDao,
    private val syncStateDao: ThreatFeedSyncStateDao
) {
    suspend fun lookupHash(sha256: String?, md5: String?): MalwareHashEntity? = withContext(Dispatchers.IO) {
        val sha = sha256?.trim()?.lowercase(Locale.ROOT)
        if (!sha.isNullOrBlank() && SHA256.matches(sha)) {
            malwareHashDao.findBySha256(sha)?.let { return@withContext it }
        }
        val md = md5?.trim()?.lowercase(Locale.ROOT)
        if (!md.isNullOrBlank() && MD5.matches(md)) malwareHashDao.findByMd5(md) else null
    }

    suspend fun lookupSha256(sha256: String): MalwareHashEntity? = lookupHash(sha256, null)
    suspend fun lookupMd5(md5: String): MalwareHashEntity? = lookupHash(null, md5)

    suspend fun lookupIoc(value: String): MalwareHashEntity? = withContext(Dispatchers.IO) {
        val normalized = normalizeIoc(value)
        if (normalized.isBlank() || normalized.length > 2048) null else malwareHashDao.findByIoc(normalized)
    }

    fun observeActiveIndicatorCount(): Flow<Int> = malwareHashDao.observeActiveIndicatorCount()
    fun observeLatestSyncState(): Flow<ThreatFeedSyncStateEntity?> = syncStateDao.observeLatest()
    fun observeLastSuccessfulSyncAt(): Flow<Long?> = syncStateDao.observeLastSuccessfulSyncAt()
    suspend fun activeIndicatorCount(): Int = withContext(Dispatchers.IO) {
        malwareHashDao.countActiveIndicators()
    }

    private fun normalizeIoc(value: String): String {
        val raw = value.trim()
        if (raw.isBlank() || raw.length > 2048) return ""
        val uri = runCatching { URI(raw) }.getOrNull()
        val scheme = uri?.scheme?.lowercase(Locale.ROOT)
        val host = uri?.host
        if (scheme != null && (scheme == "http" || scheme == "https") && !host.isNullOrBlank()) {
            val userInfo = uri.rawUserInfo?.let { "$it@" }.orEmpty()
            val normalizedHost = host.lowercase(Locale.ROOT).let {
                if (it.contains(':') && !it.startsWith("[")) "[$it]" else it
            }
            val port = if (uri.port >= 0) ":" + uri.port else ""
            val path = uri.rawPath.orEmpty()
            val query = uri.rawQuery?.let { "?" + it }.orEmpty()
            val fragment = uri.rawFragment?.let { "#" + it }.orEmpty()
            // Scheme and host are case-insensitive; path and query are kept case-sensitive.
            return "$scheme://$userInfo$normalizedHost$port$path$query$fragment"
        }
        return raw.lowercase(Locale.ROOT).trimEnd('.')
    }
    companion object {
        private val SHA256 = Regex("^[a-f0-9]{64}$")
        private val MD5 = Regex("^[a-f0-9]{32}$")
    }
}
