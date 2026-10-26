package com.vibesync.antivirus.core.hashdb

import android.content.Context
import android.util.Log
import androidx.room.withTransaction
import com.vibesync.antivirus.BuildConfig
import com.vibesync.antivirus.data.local.MalwareHashDao
import com.vibesync.antivirus.data.local.MalwareHashEntity
import com.vibesync.antivirus.data.local.ThreatDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

data class HashDatabaseCapability(
    val enabled: Boolean,
    val version: Long? = null,
    val indicatorCount: Int = 0,
    val reason: String
)

data class HashDatabaseMatch(val algorithm: HashAlgorithm, val threatName: String)

class HashDatabaseManager(context: Context, private val database: ThreatDatabase) {
    private val appContext = context.applicationContext
    private val dao: MalwareHashDao = database.malwareHashDao()
    private val mutex = Mutex()
    private val preferences = appContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
    private val activeFile = File(appContext.noBackupFilesDir, "signed-hash-database/active.bundle")

    @Volatile private var loaded = false
    @Volatile private var bloom: HashDatabaseBloomFilter? = null
    @Volatile var capability: HashDatabaseCapability = initialDisabledState()
        private set

    suspend fun restoreActiveDatabase(): HashDatabaseCapability = withContext(Dispatchers.IO) {
        mutex.withLock { restoreActiveUnsafe() }
    }

    suspend fun importBundle(input: java.io.InputStream): HashDatabaseCapability = withContext(Dispatchers.IO) {
        mutex.withLock {
            if (!loaded) restoreActiveUnsafe()
            importBundleUnsafe(input)
        }
    }

    /**
     * Restores an existing signed database, or imports the bundled database on first launch.
     * Bundle bytes are verified before any record is activated or persisted.
     */
    suspend fun activateBundledDatabaseIfMissing(): HashDatabaseCapability = withContext(Dispatchers.IO) {
        mutex.withLock {
            val restored = restoreActiveUnsafe()
            if (activeFile.isFile) return@withLock restored

            try {
                appContext.assets.open(BUNDLED_DATABASE_ASSET).use { input ->
                    importBundleUnsafe(input)
                }
            } catch (error: Exception) {
                loaded = true
                bloom = null
                capability = HashDatabaseCapability(
                    enabled = false,
                    reason = "Disabled: bundled signed hash database could not be loaded or verified."
                )
                Log.e(TAG, "Bundled signed hash database is unavailable or invalid; app will continue with it inactive.", error)
                capability
            }
        }
    }

    private suspend fun importBundleUnsafe(input: java.io.InputStream): HashDatabaseCapability {
        require(BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED && BuildConfig.HASHDB_PUBLIC_KEY_B64.isNotBlank()) {
            "Disabled: a trusted hash-database Ed25519 public key is not configured."
        }
        val bundle = HashDatabaseBundleReader.read(input)
        require(HashDatabaseSignatureVerifier.verify(
            bundle.databaseBytes, bundle.detachedSignatureBytes, BuildConfig.HASHDB_PUBLIC_KEY_B64
        )) { "Signed hash database signature verification failed." }
        val parsed = HashDatabaseFormat.parse(
            bundle.databaseBytes, HashAlgorithm.fromDatabaseName(bundle.databaseName)
        )
        val acceptedVersion = preferences.getLong(KEY_LAST_VERSION, 0L)
        require(parsed.version > acceptedVersion) {
            "Hash database version rollback or replay was rejected."
        }

        val nextBloom = HashDatabaseBloomFilter.fromRecords(parsed.records)
        replaceDatabaseRecords(parsed.records)
        try {
            writeActiveBundle(bundle.archiveBytes)
            val saved = preferences.edit().putLong(KEY_LAST_VERSION, parsed.version).commit()
            check(saved) { "Could not persist accepted hash database version." }
        } catch (error: Exception) {
            bloom = null
            capability = HashDatabaseCapability(
                enabled = false,
                reason = "Signed database activation did not complete; local database matching is disabled."
            )
            loaded = false
            throw IllegalStateException("Signed database activation failed closed.", error)
        }
        bloom = nextBloom
        loaded = true
        capability = HashDatabaseCapability(
            enabled = true,
            version = parsed.version,
            indicatorCount = parsed.records.size,
            reason = "Signed local hash database active."
        )
        return capability
    }

    suspend fun lookup(sha256: String?, md5: String?, sha1: String?, fileSize: Long? = null): HashDatabaseMatch? {
        if (!loaded) restoreActiveDatabase()
        val filter = bloom ?: return null
        val candidates = listOf(
            HashAlgorithm.SHA256 to sha256,
            HashAlgorithm.MD5 to md5,
            HashAlgorithm.SHA1 to sha1
        )
        for ((algorithm, digest) in candidates) {
            if (digest.isNullOrBlank()) continue
            val normalized = digest.lowercase(java.util.Locale.ROOT)
            if (!filter.mightContain(algorithm.token + ":" + normalized)) continue
            val row = when (algorithm) {
                HashAlgorithm.SHA256 -> dao.findSignedBySha256(normalized, fileSize)
                HashAlgorithm.MD5 -> dao.findSignedByMd5(normalized, fileSize)
                HashAlgorithm.SHA1 -> dao.findSignedBySha1(normalized, fileSize)
            }
            if (row != null && row.source == HASH_DATABASE_SOURCE) {
                return HashDatabaseMatch(algorithm, row.threatName)
            }
        }
        return null
    }

    private suspend fun restoreActiveUnsafe(): HashDatabaseCapability {
        loaded = true
        if (!BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED || BuildConfig.HASHDB_PUBLIC_KEY_B64.isBlank()) {
            bloom = null
            capability = initialDisabledState()
            return capability
        }
        if (!activeFile.isFile || !activeFile.canRead()) {
            bloom = null
            capability = HashDatabaseCapability(
                enabled = false,
                reason = "Disabled: no signed production hash database is bundled or imported."
            )
            return capability
        }
        return try {
            val bundle = activeFile.inputStream().use { HashDatabaseBundleReader.read(it) }
            require(HashDatabaseSignatureVerifier.verify(
                bundle.databaseBytes, bundle.detachedSignatureBytes, BuildConfig.HASHDB_PUBLIC_KEY_B64
            )) { "Signature verification failed." }
            val parsed = HashDatabaseFormat.parse(
                bundle.databaseBytes, HashAlgorithm.fromDatabaseName(bundle.databaseName)
            )
            val acceptedVersion = preferences.getLong(KEY_LAST_VERSION, 0L)
            require(parsed.version >= acceptedVersion) { "Downgrade rejected." }
            replaceDatabaseRecords(parsed.records)
            check(preferences.edit().putLong(KEY_LAST_VERSION, parsed.version).commit())
            bloom = HashDatabaseBloomFilter.fromRecords(parsed.records)
            capability = HashDatabaseCapability(
                enabled = true,
                version = parsed.version,
                indicatorCount = parsed.records.size,
                reason = "Signed local hash database active."
            )
            capability
        } catch (_: Exception) {
            bloom = null
            capability = HashDatabaseCapability(
                enabled = false,
                reason = "Disabled: stored signature database failed integrity, version, or format checks."
            )
            capability
        }
    }

    private suspend fun replaceDatabaseRecords(records: List<HashDatabaseRecord>) {
        val timestamp = System.currentTimeMillis()
        database.withTransaction {
            dao.deleteSource(HASH_DATABASE_SOURCE)
            records.chunked(500).forEach { batch ->
                dao.upsertBatch(batch.map { row ->
                    MalwareHashEntity(
                        indicatorKey = "$HASH_DATABASE_SOURCE:${row.bloomKey}",
                        sha256Hash = row.hash.takeIf { row.algorithm == HashAlgorithm.SHA256 },
                        md5Hash = row.hash.takeIf { row.algorithm == HashAlgorithm.MD5 },
                        fileSize = row.fileSize,
                        iocValue = row.hash.takeIf { row.algorithm == HashAlgorithm.SHA1 },
                        iocType = "sha1_hash".takeIf { row.algorithm == HashAlgorithm.SHA1 },
                        threatName = row.threatName,
                        source = HASH_DATABASE_SOURCE,
                        firstSeenAt = null,
                        lastSeenAt = null,
                        updatedAt = timestamp
                    )
                })
            }
        }
    }

    private fun writeActiveBundle(bytes: ByteArray) {
        val parent = activeFile.parentFile ?: throw IllegalStateException("Missing private database directory.")
        if (!parent.exists() && !parent.mkdirs()) throw IllegalStateException("Could not create private database directory.")
        val temporary = File(parent, "active.bundle.pending")
        FileOutputStream(temporary).use { output ->
            output.write(bytes)
            output.fd.sync()
        }
        try {
            Files.move(temporary.toPath(), activeFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(temporary.toPath(), activeFile.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    private fun initialDisabledState(): HashDatabaseCapability = HashDatabaseCapability(
        enabled = false,
        reason = if (BuildConfig.HASHDB_PUBLIC_KEY_CONFIGURED && BuildConfig.HASHDB_PUBLIC_KEY_B64.isNotBlank()) {
            "Disabled: no signed production hash database is bundled or imported."
        } else {
            "Disabled: trusted hash-database Ed25519 public key is not configured."
        }
    )

    companion object {
        const val HASH_DATABASE_SOURCE = "signed-hashdb"
        private const val PREFERENCES = "safe_mobile_signed_hash_database"
        private const val KEY_LAST_VERSION = "last_accepted_version"
    }
}
