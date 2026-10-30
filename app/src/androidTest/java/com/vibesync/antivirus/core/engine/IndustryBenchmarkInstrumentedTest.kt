package com.vibesync.antivirus.core.engine

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.vibesync.antivirus.SafeMobileApp
import com.vibesync.antivirus.core.crypto.EncryptedHashStore
import com.vibesync.antivirus.data.repository.ThreatIntelligenceRepository
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Only APK data is read; the malware is never installed or executed. */
@RunWith(AndroidJUnit4::class)
class IndustryBenchmarkInstrumentedTest {
    @Test fun scanBatch() = runBlocking {
        val ctx = ApplicationProvider.getApplicationContext<Context>()
        val app = ctx.applicationContext as SafeMobileApp
        val dir = File(requireNotNull(ctx.getExternalFilesDir(null)), "industry-benchmark")
        val inputs = JSONObject(File(dir, "batch.json").readText()).getJSONArray("samples")
        assertEquals(25, inputs.length())
        val scanner = PackageScanner(app, app.database.threatDao(), EncryptedHashStore(app),
            threatIntelligenceRepository = ThreatIntelligenceRepository(
                app.database.malwareHashDao(), app.database.threatFeedSyncStateDao()),
            hashDatabaseManager = app.hashDatabaseManager)
        val outputs = JSONArray()
        for (i in 0 until inputs.length()) {
            val sample = inputs.getJSONObject(i)
            val id = sample.getString("sample_id")
            assertTrue(id.matches(Regex("[bm][0-9]{4}")))
            val apk = File(dir, "$id.apk")
            assertTrue(apk.isFile && apk.canonicalFile.parentFile == dir.canonicalFile)
            // Stream hash instead of loading untrusted APKs into memory.
            val sha = MessageDigest.getInstance("SHA-256")
            apk.inputStream().use { f ->
                val buffer = ByteArray(65536)
                while (true) {
                    val n = f.read(buffer)
                    if (n < 0) break
                    sha.update(buffer, 0, n)
                }
            }
            val sha256 = sha.digest().joinToString("") { "%02x".format(it) }
            assertEquals(sample.getString("sha256"), sha256)
            val result = scanner.scanFile(apk, persistAllAudit = false)
            // Trust-list bypasses and missing hashes are unscanned, never counted as clean.
            val actualVerdict = if (!result.trustedByUser && result.sha256 == sha256)
                result.verdict.name else "NOT_SCANNED"
            outputs.put(JSONObject().put("sample_id", id)
                .put("label", sample.getString("label"))
                .put("sha256", sha256)
                .put("verdict", actualVerdict)
                .put("duration_ms", result.durationMs)
                .put("yara_state", result.riskReport?.yaraResult?.state?.name ?: "NOT_SCANNED")
                .put("ml_scored", result.mlProbability != null))
        }
        File(dir, "batch-results.json").writeText(JSONObject().put("samples", outputs).toString())
    }
}
