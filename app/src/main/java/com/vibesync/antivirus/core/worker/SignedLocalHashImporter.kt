package com.vibesync.antivirus.core.worker

import android.content.Context
import androidx.room.withTransaction
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.data.local.MalwareHashEntity
import com.vibesync.antivirus.data.local.ThreatDatabase
import com.vibesync.antivirus.data.local.ThreatFeedStagingEntity
import com.vibesync.antivirus.data.local.ThreatFeedSyncStateEntity
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Signed SAF import: validate detached signature and payload digest BEFORE any row becomes active.
 * Staging and final promotion use Room transactions; failed imports retain the previous snapshot.
 * The trusted public key is the same pinned Ed25519 root used for signed HTTPS feed updates.
 */
class SignedLocalHashImporter(private val database: ThreatDatabase) {
    suspend fun import(stream: InputStream): Int = withContext(Dispatchers.IO) {
        val bundle = SignedHashBundleReader.read(stream, BuildConfig.FEED_MANIFEST_PUBLIC_KEY_B64)
        val stateKey = "manual:" + bundle.manifest.sourceKey
        val source = "signed-manual:" + bundle.manifest.sourceKey
        val stateDao = database.threatFeedSyncStateDao()
        val stagingDao = database.threatFeedStagingDao()
        val hashDao = database.malwareHashDao()
        val importId = UUID.randomUUID().toString()
        val attemptedAt = System.currentTimeMillis()
        try {
            // Reject rollback before parsing. Repeat inside the commit transaction for concurrent imports.
            val previous = stateDao.get(stateKey)
            require(bundle.manifest.version > (previous?.feedVersion ?: 0L)) {
                "Signed manual definition replay or downgrade rejected."
            }
            val count = SignedHashFormatParser().parse(
                ByteArrayInputStream(bundle.payload), bundle.format, source
            ) { batch ->
                val staged = batch.map { it.toStaged(importId, attemptedAt) }
                database.withTransaction { stagingDao.upsertBatch(staged) }
            }
            database.withTransaction {
                val current = stateDao.get(stateKey)
                require(bundle.manifest.version > (current?.feedVersion ?: 0L)) {
                    "Signed manual definition replay or downgrade rejected."
                }
                // Snapshot promotion and state advance are one atomic operation.
                hashDao.deleteSource(source)
                var cursor = ""
                while (true) {
                    val page = stagingDao.nextBatch(importId, cursor, 500)
                    if (page.isEmpty()) break
                    hashDao.upsertBatch(page.map { it.toIndicator() })
                    cursor = page.last().indicatorKey
                }
                stagingDao.deleteForImport(importId)
                stateDao.upsert(
                    ThreatFeedSyncStateEntity(
                        sourceKey = stateKey,
                        sourceHost = "signed-manual",
                        lastAttemptAt = attemptedAt,
                        lastSuccessAt = System.currentTimeMillis(),
                        status = "SUCCESS",
                        lastImportedCount = count,
                        feedVersion = bundle.manifest.version,
                        feedManifestSha256 = bundle.manifest.rawManifestSha256
                    )
                )
            }
            count
        } finally {
            // A failure never promotes unsigned/unverified rows; only this import's staging is removed.
            runCatching { stagingDao.deleteForImport(importId) }
        }
    }

    private fun MalwareHashEntity.toStaged(importId: String, timestamp: Long) = ThreatFeedStagingEntity(
        importId = importId,
        indicatorKey = indicatorKey,
        sha256Hash = sha256Hash,
        md5Hash = md5Hash,
        sha1Hash = sha1Hash,
        fileSize = fileSize,
        iocValue = null,
        iocType = null,
        threatName = threatName,
        source = source,
        updatedAt = timestamp,
        stagedAt = timestamp
    )

    private fun ThreatFeedStagingEntity.toIndicator() = MalwareHashEntity(
        indicatorKey = indicatorKey,
        sha256Hash = sha256Hash,
        sha1Hash = sha1Hash,
        md5Hash = md5Hash,
        fileSize = fileSize,
        threatName = threatName,
        source = source,
        updatedAt = updatedAt
    )
}
