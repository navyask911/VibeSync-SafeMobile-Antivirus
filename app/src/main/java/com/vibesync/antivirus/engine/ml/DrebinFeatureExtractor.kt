package com.vibesync.antivirus.engine.ml

import android.content.Context
import com.vibesync.antivirus.core.engine.DrebinApkExtractor
import com.vibesync.antivirus.core.engine.DrebinFeatureContract
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

/**
 * Offline Drebin-215 extraction. An all-zero vector is valid only when every
 * supplied APK component parsed successfully and no schema feature matched.
 * Unreadable or malformed components return an explicit failure outcome.
 */
internal class DrebinFeatureExtractor(context: Context) {
    private val appContext = context.applicationContext

    fun extractFeatures(apkFile: File): DrebinApkExtractor.Outcome =
        runBlocking(Dispatchers.IO) { extractFeaturesAsync(apkFile) }

    suspend fun extractFeaturesAsync(apkFile: File): DrebinApkExtractor.Outcome =
        extractFeaturesAsync(listOf(apkFile))

    suspend fun extractFeaturesAsync(apkFiles: List<File>): DrebinApkExtractor.Outcome =
        withContext(Dispatchers.IO) {
            val schema = DrebinFeatureContract.loadSchema(appContext.assets)
                ?: return@withContext DrebinApkExtractor.Outcome.Unscannable(
                    DrebinApkExtractor.Reason.SCHEMA_INVALID
                )
            DrebinApkExtractor.extract(apkFiles, schema)
        }
}
