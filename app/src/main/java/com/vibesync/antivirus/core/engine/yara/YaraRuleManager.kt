package com.vibesync.antivirus.core.engine.yara

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.revengi.abhi.yarax.Compiler
import org.revengi.abhi.yarax.Rules
import org.revengi.abhi.yarax.Scanner
import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * Owns one compiled YARA-X ruleset. Scanner instances are created and closed
 * per component; a mutex serializes calls through the native rules handle.
 */
class YaraRuleManager(context: Context) {

    private val appContext = context.applicationContext
    private val compileMutex = Mutex()
    private val scanMutex = Mutex()

    @Volatile
    private var compiledRules: Rules? = null

    suspend fun scanBytes(bytes: ByteArray): String = withContext(Dispatchers.IO) {
        require(bytes.isNotEmpty()) { "Cannot scan an empty APK component." }
        scanMutex.withLock {
            val rules = loadOrCompileRules()
            val scanner = Scanner(rules)
            try {
                check(scanner.setTimeout(SCAN_TIMEOUT_SECONDS).isNullOrEmpty()) {
                    "YARA-X timeout configuration failed."
                }
                check(scanner.setMaxMatchesPerPattern(MAX_MATCHES_PER_PATTERN).isNullOrEmpty()) {
                    "YARA-X match limit configuration failed."
                }
                check(scanner.useMmap(false).isNullOrEmpty()) {
                    "YARA-X memory-mapping disablement failed."
                }
                scanner.scanBytes(bytes)
                    ?: throw IOException("YARA-X returned no scan response.")
            } finally {
                scanner.close()
            }
        }
    }

    suspend fun close() = withContext(Dispatchers.IO) {
        scanMutex.withLock {
            compileMutex.withLock {
                compiledRules?.close()
                compiledRules = null
            }
        }
    }

    private suspend fun loadOrCompileRules(): Rules = compileMutex.withLock {
        compiledRules?.let { if (it.isOpen) return@withLock it }

        val names = appContext.assets.list(RULES_ASSET_DIRECTORY)
            .orEmpty()
            .filter { it.endsWith(".yar", true) || it.endsWith(".yara", true) }
            .sorted()
        require(names.isNotEmpty()) { "No bundled YARA-X rules were found." }
        require(names.size <= MAX_RULE_FILES) { "Too many bundled YARA-X rule files." }

        val compiler = Compiler()
        var compilerConsumed = false
        try {
            var totalSourceBytes = 0
            for ((index, name) in names.withIndex()) {
                compiler.newNamespace("safemobile_rules_${index + 1}")
                val source = readRuleSource("$RULES_ASSET_DIRECTORY/$name")
                totalSourceBytes += source.toByteArray(Charsets.UTF_8).size
                require(totalSourceBytes <= MAX_TOTAL_RULE_BYTES) {
                    "Bundled YARA-X rules exceed the aggregate source limit."
                }

                // The vendored Compiler wrapper maps newNamespace to the exact
                // createNamespace JNI export in the pinned Rust wrapper.
                val error = compiler.addSource(source)
                check(error.isNullOrBlank()) {
                    "YARA-X rejected $name: ${error.orEmpty().take(500)}"
                }
            }

            val rules = compiler.build()
            compilerConsumed = true
            compiledRules = rules
            rules
        } finally {
            if (!compilerConsumed) compiler.close()
        }
    }

    private fun readRuleSource(assetPath: String): String {
        val output = ByteArrayOutputStream()
        appContext.assets.open(assetPath).use { input ->
            val buffer = ByteArray(BUFFER_SIZE)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                if (output.size() + count > MAX_RULE_FILE_BYTES) {
                    throw IOException("YARA-X rule file exceeds its size limit: $assetPath")
                }
                output.write(buffer, 0, count)
            }
        }
        return output.toByteArray().toString(Charsets.UTF_8)
    }

    private companion object {
        const val RULES_ASSET_DIRECTORY = "yara_rules"
        const val BUFFER_SIZE = 8192
        const val MAX_RULE_FILES = 128
        const val MAX_RULE_FILE_BYTES = 256 * 1024
        const val MAX_TOTAL_RULE_BYTES = 2 * 1024 * 1024
        const val SCAN_TIMEOUT_SECONDS = 8
        const val MAX_MATCHES_PER_PATTERN = 32
    }
}
