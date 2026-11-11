package com.vibesync.antivirus.core.posture

import android.content.Context
import android.util.AtomicFile
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.crypto.tink.integration.android.AndroidKeystoreKmsClient
import com.google.crypto.tink.integration.android.SharedPrefKeysetReader
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException

interface PostureSnapshotStore {
    fun read(): PostureSnapshot?
    fun write(snapshot: PostureSnapshot)
}

/** Authenticated encryption, Keystore-wrapped keyset, atomic replacement, and no-backup storage. */
class EncryptedPostureSnapshotStore(context: Context,
    storageFile: File = File(context.noBackupFilesDir, "device_posture_snapshot_v1.bin"),
    private val keysetPreferences: String = KEYSET_PREFS) : PostureSnapshotStore {
    private val app = context.applicationContext
    private val file = AtomicFile(storageFile)
    private val aad = ("safemobile.posture.snapshot.v1:" + app.packageName).toByteArray(Charsets.UTF_8)
    private val aead: Aead by lazy(LazyThreadSafetyMode.SYNCHRONIZED) {
        AeadConfig.register()
        val manager = AndroidKeysetManager.Builder().withKeyTemplate(KeyTemplates.get("AES256_GCM"))
            .withSharedPref(app, "posture_keyset", keysetPreferences)
            .withMasterKeyUri(MASTER_URI).build()
        if (!manager.isUsingKeystore) {
            // Tink can fall back to cleartext keysets. This module explicitly refuses that mode.
            app.getSharedPreferences(keysetPreferences, Context.MODE_PRIVATE).edit().clear().commit()
            throw GeneralSecurityException("Android Keystore protection is unavailable")
        }
        // isUsingKeystore alone does not rule out Tink's legacy cleartext-read fallback.
        // Read again through the encrypted-only API: a cleartext keyset must never be accepted.
        @Suppress("DEPRECATION")
        val wrappedHandle = KeysetHandle.read(SharedPrefKeysetReader(app, "posture_keyset", keysetPreferences),
            AndroidKeystoreKmsClient().getAead(MASTER_URI))
        wrappedHandle.getPrimitive(Aead::class.java)
    }

    override fun read(): PostureSnapshot? {
        // AtomicFile.openRead may restore a pending backup; only a truly missing state is a first baseline.
        val encrypted = try {
            file.openRead().use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > MAX_BYTES) throw IOException("Encrypted posture snapshot is too large")
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        } catch (missing: java.io.FileNotFoundException) {
            if (!file.baseFile.exists()) return null else throw missing
        }
        return PostureSnapshotCodec.decode(aead.decrypt(encrypted, aad))
    }

    override fun write(snapshot: PostureSnapshot) {
        val plain = PostureSnapshotCodec.encode(snapshot)
        require(plain.size <= MAX_BYTES - 1024) { "Posture snapshot is too large" }
        val encrypted = aead.encrypt(plain, aad)
        val stream = file.startWrite()
        try { stream.write(encrypted); file.finishWrite(stream) }
        catch (error: Exception) { file.failWrite(stream); throw error }
    }

    companion object {
        private const val KEYSET_PREFS = "safe_mobile_posture_keyset"
        private const val MASTER_URI = "android-keystore://safemobile_posture_master_v1"
        private const val MAX_BYTES = 2 * 1024 * 1024
    }
}
