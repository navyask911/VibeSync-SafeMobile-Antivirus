package com.vibesync.antivirus.core.engine

import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Locale

/** A deliberately strict, bounded YARA-compatible literal/boolean subset, NOT libyara. */
enum class YaraScanState { MATCHES, NO_MATCH, DISABLED, NOT_SCANNED }

data class YaraRuleMatch(
    val ruleName: String,
    val severity: RiskSeverity,
    val description: String,
    val mitreTechnique: String,
    /** Rule string identifiers and authored patterns, never arbitrary matched file contents. */
    val matchedPatterns: List<String>
)

data class YaraScanResult(
    val state: YaraScanState,
    val matches: List<YaraRuleMatch> = emptyList(),
    val reason: String? = null
) {
    val matchedRules: List<String> get() = matches.map { it.ruleName }
}

private sealed interface YaraCondition {
    fun matches(found: Set<String>): Boolean
}
private data class YaraRef(val id: String) : YaraCondition {
    override fun matches(found: Set<String>) = id in found
}
private data class YaraAnd(val left: YaraCondition, val right: YaraCondition) : YaraCondition {
    override fun matches(found: Set<String>) = left.matches(found) && right.matches(found)
}
private data class YaraOr(val left: YaraCondition, val right: YaraCondition) : YaraCondition {
    override fun matches(found: Set<String>) = left.matches(found) || right.matches(found)
}
private data class CompiledYaraRule(
    val name: String,
    val severity: RiskSeverity,
    val description: String,
    val mitre: String,
    val patterns: Map<String, ByteArray>,
    val condition: YaraCondition
)

private class BoundedYaraConditionParser(
    private val tokens: List<String>, private val defined: Set<String>
) {
    private var offset = 0
    fun parse(): YaraCondition {
        val parsed = parseOr()
        require(offset == tokens.size) { "Trailing or unsupported YARA condition token." }
        return parsed
    }
    private fun parseOr(): YaraCondition {
        var node = parseAnd()
        while (take("or")) node = YaraOr(node, parseAnd())
        return node
    }
    private fun parseAnd(): YaraCondition {
        var node = parseAtom()
        while (take("and")) node = YaraAnd(node, parseAtom())
        return node
    }
    private fun parseAtom(): YaraCondition {
        if (take("(")) {
            val node = parseOr()
            require(take(")")) { "Unclosed YARA condition parenthesis." }
            return node
        }
        require(offset < tokens.size) { "Missing YARA condition operand." }
        val id = tokens[offset++]
        require(id.startsWith("$") && id in defined) { "Undefined or unsupported YARA pattern reference: " + id }
        return YaraRef(id)
    }
    private fun take(value: String): Boolean {
        if (offset < tokens.size && tokens[offset].equals(value, true)) { offset++; return true }
        return false
    }
}

class YaraScanner private constructor(
    private val rules: List<CompiledYaraRule>?,
    private val disabledReason: String
) {
    constructor() : this(null, DISABLED_REASON)
    val ruleCount: Int get() = rules?.size ?: 0

    fun scan(file: File): YaraScanResult {
        if (!file.isFile || !file.canRead()) return YaraScanResult(YaraScanState.NOT_SCANNED, reason = "Input is unavailable.")
        if (rules == null) return YaraScanResult(YaraScanState.DISABLED, reason = disabledReason)
        if (file.length() !in 8..MAX_DEX_BYTES.toLong()) {
            return YaraScanResult(YaraScanState.NOT_SCANNED, reason = "DEX is empty or exceeds the scan bound.")
        }
        return try {
            file.inputStream().use { input ->
                val bytes = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    if (n == 0) continue
                    if (bytes.size().toLong() + n > MAX_DEX_BYTES) {
                        return YaraScanResult(YaraScanState.NOT_SCANNED, reason = "DEX size limit exceeded.")
                    }
                    bytes.write(buffer, 0, n)
                }
                scanDex(bytes.toByteArray())
            }
        } catch (e: java.io.IOException) {
            YaraScanResult(YaraScanState.NOT_SCANNED, reason = "DEX read failed.")
        }
    }

    /** Called with an already bounded, extracted classes*.dex entry on a background IO dispatcher. */
    fun scanDex(bytes: ByteArray): YaraScanResult {
        val compiled = rules ?: return YaraScanResult(YaraScanState.DISABLED, reason = disabledReason)
        if (bytes.size !in 8..MAX_DEX_BYTES || !isDex(bytes)) {
            return YaraScanResult(YaraScanState.NOT_SCANNED, reason = "No valid DEX magic or DEX scan limit exceeded.")
        }
        val cache = HashMap<String, Boolean>()
        val matches = compiled.mapNotNull { rule ->
            val found = rule.patterns.filter { (_, needle) ->
                val key = needle.toString(StandardCharsets.ISO_8859_1)
                cache.getOrPut(key) { containsBytes(bytes, needle) }
            }.keys.toSet()
            if (!rule.condition.matches(found)) null
            else YaraRuleMatch(
                rule.name, rule.severity, rule.description, rule.mitre,
                rule.patterns.filterKeys { it in found }.entries.take(8).map { (id, value) ->
                    id + "=\"" + value.toString(StandardCharsets.US_ASCII).take(64) + "\""
                }
            )
        }
        return YaraScanResult(
            if (matches.isEmpty()) YaraScanState.NO_MATCH else YaraScanState.MATCHES,
            matches
        )
    }

    companion object {
        const val MAX_RULE_BYTES = 128 * 1024
        const val MAX_DEX_BYTES = 16 * 1024 * 1024
        const val DISABLED_REASON = "No validated bundled DEX rule pack has been loaded."
        private const val MAX_RULES = 32
        private const val MAX_PATTERNS = 16
        private val RULE = Regex("""rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^{}]*)\}""", RegexOption.DOT_MATCHES_ALL)
        private val SECTION = Regex("""(?m)^\s*(meta|strings|condition)\s*:\s*$""")
        private val META = Regex("""([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"([^"\r\n]*)"""")
        private val PATTERN = Regex("""(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"\r\n]+)"\s+ascii""")
        private val TOKEN = Regex("""\$[A-Za-z_][A-Za-z0-9_]*|\(|\)|\b(?:and|or)\b""", RegexOption.IGNORE_CASE)

        fun fromRules(text: String): YaraScanner {
            require(text.toByteArray(StandardCharsets.UTF_8).size <= MAX_RULE_BYTES) { "YARA asset exceeds size limit." }
            require(text.none { it == '\u0000' }) { "YARA asset includes a NUL byte." }
            val compiled = mutableListOf<CompiledYaraRule>()
            var cursor = 0
            for (match in RULE.findAll(text)) {
                require(text.substring(cursor, match.range.first).isBlank()) { "Unsupported content outside a YARA rule." }
                cursor = match.range.last + 1
                val name = match.groupValues[1]
                require(compiled.none { it.name == name }) { "Duplicate YARA rule name." }
                val body = match.groupValues[2]
                val headings = SECTION.findAll(body).toList()
                require(headings.size == 3 && headings.map { it.groupValues[1] } == listOf("meta", "strings", "condition")) {
                    "Unsupported YARA sections; expected meta, strings, condition."
                }
                require(body.substring(0, headings.first().range.first).isBlank())
                fun section(index: Int): String {
                    val start = headings[index].range.last + 1
                    val end = if (index == 2) body.length else headings[index + 1].range.first
                    return body.substring(start, end).trim()
                }
                val meta = linkedMapOf<String, String>()
                for (line in section(0).lines().map(String::trim).filter(String::isNotBlank)) {
                    val item = META.matchEntire(line) ?: error("Unsupported YARA metadata in " + name)
                    require(meta.put(item.groupValues[1], item.groupValues[2]) == null) { "Duplicate metadata." }
                }
                val severity = when (meta["severity"]?.lowercase(Locale.ROOT)) {
                    "low" -> RiskSeverity.LOW
                    "medium" -> RiskSeverity.MEDIUM
                    "high", "critical" -> RiskSeverity.HIGH
                    else -> error("Missing/unsupported rule severity in " + name)
                }
                val description = requireNotNull(meta["description"]).also { require(it.length in 1..200) }
                val mitre = meta["mitre"].orEmpty().also { require(it.length <= 40) }
                val patterns = linkedMapOf<String, ByteArray>()
                for (line in section(1).lines().map(String::trim).filter(String::isNotBlank)) {
                    val item = PATTERN.matchEntire(line) ?: error("Unsupported pattern syntax in " + name)
                    val literal = item.groupValues[2]
                    require(literal.length in 3..128 && literal.all { it.code in 32..126 }) { "Only bounded ASCII literals are supported." }
                    require(patterns.put(item.groupValues[1], literal.toByteArray(StandardCharsets.US_ASCII)) == null) {
                        "Duplicate pattern identifier."
                    }
                }
                require(patterns.size in 1..MAX_PATTERNS) { "Invalid pattern count for " + name }
                val conditionText = section(2)
                val tokens = mutableListOf<String>()
                var start = 0
                for (token in TOKEN.findAll(conditionText)) {
                    require(conditionText.substring(start, token.range.first).isBlank()) { "Unsupported YARA condition syntax." }
                    tokens += token.value
                    start = token.range.last + 1
                }
                require(conditionText.substring(start).isBlank() && tokens.isNotEmpty()) { "Unsupported/empty YARA condition." }
                val condition = BoundedYaraConditionParser(tokens, patterns.keys).parse()
                compiled += CompiledYaraRule(name, severity, description, mitre, patterns, condition)
                require(compiled.size <= MAX_RULES) { "Too many YARA rules." }
            }
            require(text.substring(cursor).isBlank() && compiled.isNotEmpty()) { "Unparsed content or empty YARA rule asset." }
            return YaraScanner(compiled.toList(), "")
        }

        private fun isDex(bytes: ByteArray) =
            bytes[0] == 'd'.code.toByte() && bytes[1] == 'e'.code.toByte() &&
                bytes[2] == 'x'.code.toByte() && bytes[3] == '\n'.code.toByte() &&
                bytes[4] == '0'.code.toByte() && bytes[5] in '0'.code.toByte()..'9'.code.toByte() &&
                bytes[6] in '0'.code.toByte()..'9'.code.toByte() && bytes[7] == 0.toByte()

        private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
            if (needle.size > haystack.size) return false
            var i = 0
            val last = haystack.size - needle.size
            while (i <= last) {
                if (haystack[i] == needle[0]) {
                    var j = 1
                    while (j < needle.size && haystack[i + j] == needle[j]) j++
                    if (j == needle.size) return true
                }
                i++
            }
            return false
        }
    }
}
