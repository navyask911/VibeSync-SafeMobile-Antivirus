package com.vibesync.antivirus.core.engine

import android.content.Context
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.UUID

/** Stores user-selected YARA text for future review only; this class never compiles or executes rules. */
class YaraRuleImportStore(context: Context) {
    private val root = File(context.noBackupFilesDir, "yara-rules/pending")

    fun importPending(input: InputStream): File {
        val bytes = input.use { source ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            var total = 0
            while (true) {
                val count = source.read(buffer)
                if (count < 0) break
                if (count == 0) continue
                total += count
                require(total <= MAX_RULE_BYTES) { "Rule file exceeds the size limit." }
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        require(bytes.isNotEmpty()) { "Rule file is empty." }
        val decoded = StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        require(decoded.none { it == '\u0000' || (Character.isISOControl(it) && it !in setOf('\n', '\r', '\t')) }) {
            "Rule file contains binary/control content."
        }
        require(Regex("(?m)^\\s*rule\\s+[A-Za-z_][A-Za-z0-9_]*\\b").containsMatchIn(decoded)) {
            "No YARA rule declaration was found. The file is stored only after basic text validation."
        }
        if (!root.exists() && !root.mkdirs()) throw IllegalStateException("Could not create private pending-rule directory.")
        val destination = File(root, "pending-${UUID.randomUUID()}.yar")
        val temporary = File(root, "${destination.name}.tmp")
        try {
            FileOutputStream(temporary).use { out -> out.write(bytes); out.fd.sync() }
            if (!temporary.renameTo(destination)) throw IllegalStateException("Could not store pending YARA rule file.")
            return destination
        } finally {
            if (temporary.exists()) temporary.delete()
        }
    }

    fun pendingCount(): Int = root.listFiles()?.count { it.isFile && it.extension == "yar" } ?: 0

    companion object {
        const val MAX_RULE_BYTES = 2 * 1024 * 1024
    }
}