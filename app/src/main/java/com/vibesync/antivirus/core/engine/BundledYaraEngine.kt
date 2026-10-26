package com.vibesync.antivirus.core.engine

import android.content.res.AssetManager
import java.io.ByteArrayOutputStream
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

data class YaraCapability(val active: Boolean, val ruleCount: Int, val reason: String)

/**
 * Bundled assets only; user-imported pending rules are never executed.
 * Content is authenticated by the signed APK, not by a remote rule service.
 */
object BundledYaraEngine {
    private const val ASSET_PATH = "yara/safemobile_android_dex.yar"
    @Volatile private var engine: YaraScanner = YaraScanner()
    @Volatile var capability: YaraCapability = YaraCapability(false, 0, YaraScanner.DISABLED_REASON)
        private set

    fun initialize(assets: AssetManager) {
        try {
            val bytes = assets.open(ASSET_PATH).use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(4096)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (n == 0) continue
                    require(output.size() + n <= YaraScanner.MAX_RULE_BYTES) { "Oversized bundled rules." }
                    output.write(buffer, 0, n)
                }
                output.toByteArray()
            }
            val source = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
            val validated = YaraScanner.fromRules(source)
            engine = validated
            capability = YaraCapability(true, validated.ruleCount, "Bundled MIT-licensed DEX-only literal signatures; advisory matches, not full YARA or a malware verdict.")
        } catch (error: Exception) {
            engine = YaraScanner()
            capability = YaraCapability(false, 0, "Bundled rule validation failed: " + (error.message ?: "unknown error"))
        }
    }

    fun scanDex(bytes: ByteArray): YaraScanResult = engine.scanDex(bytes)
}
