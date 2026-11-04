package com.vibesync.antivirus.engine.ml

import android.content.Context
import com.vibesync.antivirus.core.engine.DrebinApkExtractor
import com.vibesync.antivirus.core.engine.DrebinFeatureContract
import java.io.File
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Extracts the model's exact Drebin-215 feature order from a local APK.
 *
 * Manifest parsing and DEX traversal are delegated to the application's bounded,
 * binary-XML-aware extractor and the release-pinned feature contract. No APK code
 * is executed and no APK contents leave the device.
 *
 * Corrupt, unreadable, oversized, or otherwise unscannable APKs produce the
 * requested all-zero vector rather than crashing the scan pipeline. Callers must
 * treat the returned probability as advisory; Phase 3 does not change verdicts.
 */
class DrebinFeatureExtractor(context: Context) {
    private val appContext = context.applicationContext

    fun extractFeatures(apkFile: File): FloatArray =
        kotlinx.coroutines.runBlocking(Dispatchers.IO) { extractFeaturesAsync(apkFile) }

    suspend fun extractFeaturesAsync(apkFile: File): FloatArray = withContext(Dispatchers.IO) {
        val emptyVector = FloatArray(FEATURE_COUNT)
        try {
            val schema = DrebinFeatureContract.loadSchema(appContext.assets)
                ?: return@withContext emptyVector

            when (val extracted = DrebinApkExtractor.extract(apkFile, schema)) {
                is DrebinApkExtractor.Outcome.Features -> {
                    extracted.vector.takeIf { it.size == FEATURE_COUNT } ?: emptyVector
                }
                is DrebinApkExtractor.Outcome.Unscannable -> emptyVector
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyVector
        } catch (_: LinkageError) {
            emptyVector
        }
    }

    companion object {
        const val FEATURE_COUNT = 215
    }
}
