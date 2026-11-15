package com.vibesync.antivirus.core.engine.yara

import android.content.Context
import kotlinx.coroutines.CancellationException
import org.json.JSONArray
import org.json.JSONObject

enum class YaraXScanState {
    MATCHES,
    NO_MATCH,
    DISABLED,
    NOT_SCANNED
}

data class YaraXRuleMatch(
    val ruleIdentifier: String,
    val namespace: String,
    val componentName: String,
    val tags: List<String>,
    val classification: String,
    val severity: String,
    val description: String,
    val malwareName: String?,
    val matchedPatterns: List<String>
)

data class YaraXScanResult(
    val state: YaraXScanState,
    val matches: List<YaraXRuleMatch> = emptyList(),
    val reason: String? = null
) {
    val isComplete: Boolean
        get() = state == YaraXScanState.MATCHES || state == YaraXScanState.NO_MATCH

    val threatMatches: List<YaraXRuleMatch>
        get() = matches.filter { it.classification == CLASSIFICATION_THREAT }

    val suspiciousMatches: List<YaraXRuleMatch>
        get() = matches.filter { it.classification == CLASSIFICATION_SUSPICIOUS }

    private companion object {
        const val CLASSIFICATION_THREAT = "threat"
        const val CLASSIFICATION_SUSPICIOUS = "suspicious"
    }
}

/**
 * Full YARA-X APK scan. Each selected ZIP component is passed to the native
 * YARA engine immediately after bounded streaming; unrelated ZIP entries are not buffered.
 */
class YaraScanner(context: Context) {

    private val extractor = ApkContentExtractor()
    private val ruleManager = YaraRuleManager(context.applicationContext)

    suspend fun scanApk(apk: java.io.File): YaraXScanResult {
        val allMatches = mutableListOf<YaraXRuleMatch>()
        var abortedResult: YaraXScanResult? = null

        val extraction = try {
            extractor.forEachComponent(apk) { component ->
                val response = try {
                    ruleManager.scanBytes(component.bytes)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: LinkageError) {
                    abortedResult = YaraXScanResult(
                        YaraXScanState.DISABLED,
                        allMatches.toList(),
                        "YARA-X native library is unavailable: ${error.javaClass.simpleName}."
                    )
                    return@forEachComponent false
                } catch (error: Exception) {
                    abortedResult = YaraXScanResult(
                        YaraXScanState.DISABLED,
                        allMatches.toList(),
                        "YARA-X rules could not be initialized or executed: ${error.javaClass.simpleName}."
                    )
                    return@forEachComponent false
                }

                val parsed = try {
                    parseResponse(response, component.entryName)
                } catch (error: Exception) {
                    abortedResult = YaraXScanResult(
                        YaraXScanState.NOT_SCANNED,
                        allMatches.toList(),
                        "YARA-X returned an invalid or failed scan response: ${error.javaClass.simpleName}."
                    )
                    return@forEachComponent false
                }
                allMatches += parsed
                true
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            return YaraXScanResult(
                YaraXScanState.NOT_SCANNED,
                allMatches.toList(),
                "APK streaming failed: ${error.javaClass.simpleName}."
            )
        }

        abortedResult?.let { return it }
        if (extraction is ApkExtractionOutcome.Incomplete) {
            return YaraXScanResult(
                YaraXScanState.NOT_SCANNED,
                allMatches.toList(),
                extraction.reason
            )
        }

        return YaraXScanResult(
            if (allMatches.isEmpty()) YaraXScanState.NO_MATCH else YaraXScanState.MATCHES,
            allMatches.distinctBy { it.namespace + ":" + it.ruleIdentifier + ":" + it.componentName }
        )
    }

    suspend fun close() = ruleManager.close()

    private fun parseResponse(response: String, componentName: String): List<YaraXRuleMatch> {
        val json = JSONObject(response)
        if (json.has("error")) {
            throw IllegalStateException(json.optString("error", "YARA-X scan failed."))
        }
        val matches = json.optJSONArray("matches")
            ?: throw IllegalStateException("YARA-X response omitted the matches array.")

        return buildList {
            for (index in 0 until matches.length()) {
                val rule = matches.optJSONObject(index)
                    ?: throw IllegalStateException("YARA-X returned a malformed rule match.")
                val identifier = rule.optString("identifier").takeIf(String::isNotBlank)
                    ?: throw IllegalStateException("YARA-X match has no rule identifier.")
                val metadata = rule.optJSONObject("metadata")
                val classification = normalizeClassification(
                    metadata?.optString("classification").orEmpty()
                )
                val severity = normalizeSeverity(
                    metadata?.optString("severity").orEmpty()
                )
                val tags = stringArray(rule.optJSONArray("tags"))
                val patternIds = patternIdentifiers(rule.optJSONArray("patterns"))
                val description = metadata?.optString("description")
                    ?.takeIf(String::isNotBlank)
                    ?.take(MAX_DESCRIPTION_CHARS)
                    ?: "YARA-X rule $identifier matched."
                val malwareName = metadata?.optString("malware_name")
                    ?.takeIf(String::isNotBlank)
                    ?.take(MAX_NAME_CHARS)

                add(
                    YaraXRuleMatch(
                        ruleIdentifier = identifier.take(MAX_NAME_CHARS),
                        namespace = rule.optString("namespace").take(MAX_NAME_CHARS),
                        componentName = componentName.take(MAX_NAME_CHARS),
                        tags = tags,
                        classification = classification,
                        severity = severity,
                        description = description,
                        malwareName = malwareName,
                        matchedPatterns = patternIds
                    )
                )
            }
        }
    }

    private fun stringArray(values: JSONArray?): List<String> {
        if (values == null) return emptyList()
        return buildList {
            for (index in 0 until minOf(values.length(), MAX_TAGS)) {
                val value = values.optString(index).takeIf(String::isNotBlank) ?: continue
                add(value.take(MAX_NAME_CHARS))
            }
        }
    }

    private fun patternIdentifiers(patterns: JSONArray?): List<String> {
        if (patterns == null) return emptyList()
        return buildList {
            for (index in 0 until minOf(patterns.length(), MAX_PATTERNS)) {
                val pattern = patterns.optJSONObject(index) ?: continue
                val identifier = pattern.optString("identifier").takeIf(String::isNotBlank) ?: continue
                add(identifier.take(MAX_NAME_CHARS))
            }
        }
    }

    private fun normalizeClassification(value: String): String =
        when (value.trim().lowercase()) {
            "threat" -> "threat"
            "suspicious" -> "suspicious"
            else -> "informational"
        }

    private fun normalizeSeverity(value: String): String =
        when (value.trim().lowercase()) {
            "low", "medium", "high", "critical" -> value.trim().lowercase()
            else -> "informational"
        }

    private companion object {
        const val MAX_NAME_CHARS = 120
        const val MAX_DESCRIPTION_CHARS = 240
        const val MAX_TAGS = 32
        const val MAX_PATTERNS = 32
    }
}
