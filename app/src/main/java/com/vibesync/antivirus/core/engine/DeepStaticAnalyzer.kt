package com.vibesync.antivirus.core.engine

import android.content.pm.ActivityInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.ProviderInfo
import android.content.pm.ServiceInfo
import android.os.Build
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Locale
import java.util.zip.ZipFile
import kotlin.math.ln

internal data class DeepStaticDexSample(val name: String, val bytes: ByteArray)

/**
 * Local, bounded APK metadata/structure review. It never loads or executes APK code.
 * Findings are advisory; this is not a full Android manifest/DEX verifier.
 */
class DeepStaticAnalyzer {
    fun analyze(packageInfo: PackageInfo?, apk: File?, debugCertificate: Boolean = false): RiskReport {
        val permissions = packageInfo?.requestedPermissions?.toSet().orEmpty()
        val accessibility = packageInfo?.services.orEmpty().any { it.permission == BIND_ACCESSIBILITY_SERVICE }
        val deviceAdmin = packageInfo?.receivers.orEmpty().filter { it.permission == BIND_DEVICE_ADMIN }.map { it.name.orEmpty() }
        val components = buildList {
            packageInfo?.activities.orEmpty().forEach { add(it.toExposure("activity")) }
            packageInfo?.services.orEmpty().forEach { add(it.toExposure("service")) }
            packageInfo?.receivers.orEmpty().forEach { add(it.toExposure("receiver")) }
            packageInfo?.providers.orEmpty().forEach { add(it.toExposure("provider")) }
        }
        val signerObservations = mutableListOf<String>()
        val signerPresent = packageInfo?.let { hasSignerMaterial(it) }
        if (packageInfo != null && signerPresent == true && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val history = runCatching { packageInfo.signingInfo?.signingCertificateHistory?.size ?: 0 }.getOrDefault(0)
            if (history > 1) signerObservations += "Signer certificate history contains $history certificates; rotation history is informational, not a malware verdict."
        }
        val structure = inspectApk(apk)
        val report = analyzeObservations(
            requestedPermissions = permissions,
            hasAccessibilityService = accessibility,
            deviceAdminReceivers = deviceAdmin,
            components = components,
            debugCertificate = debugCertificate,
            signerMaterialAvailable = signerPresent ?: true,
            entryNames = structure.entryNames,
            dexSamples = structure.dexSamples.map { DeepStaticDexSample(it.name, it.bytes) },
            archiveIssues = structure.issues,
            signerObservations = signerObservations
        )
        // The APK reader above already bounds DEX entry and total uncompressed sizes.
        // Scanner callers run on Dispatchers.IO and never execute target code.
        val scanned = structure.dexSamples.map { sample ->
            sample.name to BundledYaraEngine.scanDex(sample.bytes)
        }
        val matched = scanned.flatMap { it.second.matches }.distinctBy { it.ruleName }
        val yaraState = when {
            scanned.any { it.second.state == YaraScanState.MATCHES } -> YaraScanState.MATCHES
            scanned.any { it.second.state == YaraScanState.DISABLED } -> YaraScanState.DISABLED
            scanned.any { it.second.state == YaraScanState.NOT_SCANNED } -> YaraScanState.NOT_SCANNED
            scanned.isEmpty() -> YaraScanState.NOT_SCANNED
            else -> YaraScanState.NO_MATCH
        }
        val yaraResult = YaraScanResult(yaraState, matched,
            when (yaraState) {
                YaraScanState.DISABLED -> BundledYaraEngine.capability.reason
                YaraScanState.NOT_SCANNED -> "No complete valid DEX was checked by bundled rules."
                else -> null
            }
        )
        val findings = scanned.flatMap { (dexName, result) ->
            result.matches.map { hit ->
                RiskFinding(
                    ruleId = "YARA_" + hit.ruleName,
                    severity = hit.severity,
                    confidence = if (hit.severity == RiskSeverity.HIGH) 70 else 50,
                    evidence = "Limited DEX rule " + hit.ruleName + " (" + hit.mitreTechnique +
                        ") matched in " + dexName.take(120) + ". String evidence: " +
                        hit.matchedPatterns.joinToString(", ") + ". Advisory only, not malware proof."
                )
            }
        }.distinctBy { it.ruleId + it.evidence }.take(64)
        val addedRisk = when {
            findings.any { it.severity == RiskSeverity.HIGH } -> 65
            findings.any { it.severity == RiskSeverity.MEDIUM } -> 45
            findings.any { it.severity == RiskSeverity.LOW } -> 25
            else -> 0
        }
        return report.copy(
            findings = (report.findings + findings).distinctBy { it.ruleId + it.evidence },
            riskScore = maxOf(report.riskScore, addedRisk),
            observations = (report.observations + ("Bounded DEX rules: " + yaraState.name +
                "; loaded " + BundledYaraEngine.capability.ruleCount +
                "; matching " + matched.size + ". Encrypted, unloaded or native payloads may evade static checks.")).distinct(),
            limitations = report.limitations +
                "Limited DEX rules support only exact ASCII literals and boolean conditions; not full libyara or code emulation.",
            yaraResult = yaraResult
        )
    }

    private data class DexSample(val name: String, val bytes: ByteArray)
    private data class ArchiveSignals(val entryNames: Set<String>, val dexSamples: List<DexSample>, val issues: List<String>)

    private fun inspectApk(apk: File?): ArchiveSignals {
        if (apk == null) return ArchiveSignals(emptySet(), emptyList(), emptyList())
        if (!apk.isFile || !apk.canRead()) return ArchiveSignals(emptySet(), emptyList(), listOf("APK_ARCHIVE_UNREADABLE"))
        val names = linkedSetOf<String>()
        val dex = mutableListOf<DexSample>()
        val issues = mutableListOf<String>()
        var totalDexBytes = 0L
        return try {
            ZipFile(apk).use { zip ->
                val entries = zip.entries()
                var inspected = 0
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    inspected++
                    if (inspected > MAX_ARCHIVE_ENTRIES) { issues += "APK_ENTRY_COUNT_LIMIT"; break }
                    names += entry.name.take(MAX_ENTRY_NAME_CHARS)
                    if (!DEX_NAME.matches(entry.name)) continue
                    if (entry.size < 0L || entry.size > MAX_SINGLE_DEX_BYTES) {
                        issues += "DEX_SIZE_LIMIT:${entry.name.take(80)}"
                        continue
                    }
                    if (totalDexBytes + entry.size > MAX_TOTAL_DEX_BYTES) {
                        issues += "DEX_TOTAL_SIZE_LIMIT"
                        break
                    }
                    val bytes = zip.getInputStream(entry).use { readBounded(it, MAX_SINGLE_DEX_BYTES.toInt()) }
                    totalDexBytes += bytes.size.toLong()
                    dex += DexSample(entry.name.take(MAX_ENTRY_NAME_CHARS), bytes)
                }
            }
            ArchiveSignals(names, dex, issues)
        } catch (_: Exception) {
            ArchiveSignals(names, dex, issues + "APK_ARCHIVE_UNREADABLE")
        }
    }

    private fun readBounded(input: java.io.InputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream(minOf(limit, 8192))
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0) continue
            total += count
            require(total <= limit) { "DEX entry exceeded its read bound." }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private fun ComponentInfo.toExposure(kind: String): ComponentExposure = ComponentExposure(
        kind = kind,
        name = name.orEmpty().take(MAX_COMPONENT_NAME_CHARS),
        exported = exported,
        permission = when (this) { is ActivityInfo -> this.permission; is ServiceInfo -> this.permission; is ProviderInfo -> this.readPermission ?: this.writePermission; else -> null },
        readPermission = (this as? ProviderInfo)?.readPermission,
        writePermission = (this as? ProviderInfo)?.writePermission
    )

    private fun hasSignerMaterial(info: PackageInfo): Boolean = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            !info.signingInfo?.apkContentsSigners.isNullOrEmpty()
        } else {
            @Suppress("DEPRECATION")
            !info.signatures.isNullOrEmpty()
        }
    } catch (_: Exception) { false }

    companion object {
        private const val BIND_ACCESSIBILITY_SERVICE = "android.permission.BIND_ACCESSIBILITY_SERVICE"
        private const val BIND_DEVICE_ADMIN = "android.permission.BIND_DEVICE_ADMIN"
        private const val MAX_ARCHIVE_ENTRIES = 10_000
        private const val MAX_ENTRY_NAME_CHARS = 240
        private const val MAX_COMPONENT_NAME_CHARS = 180
        private const val MAX_SINGLE_DEX_BYTES = 16L * 1024L * 1024L
        private const val MAX_TOTAL_DEX_BYTES = 24L * 1024L * 1024L
        private val DEX_NAME = Regex("classes([0-9]*)\\.dex")
        private val PACKER_PATH_PATTERNS = listOf(
            Regex("^lib/[^/]+/libjiagu\\.so$", RegexOption.IGNORE_CASE) to "JIAGU_NATIVE_LIBRARY",
            Regex("^lib/[^/]+/libshella[^/]*\\.so$", RegexOption.IGNORE_CASE) to "SHELLA_NATIVE_LIBRARY",
            Regex("^lib/[^/]+/libprotectClass\\.so$", RegexOption.IGNORE_CASE) to "PROTECTED_CLASS_NATIVE_LIBRARY",
            Regex("^lib/[^/]+/libsecexe\\.so$", RegexOption.IGNORE_CASE) to "SECEXE_NATIVE_LIBRARY",
            Regex("^assets/[^/]*(ijiami|bangcle|secexe|jiagu)[^/]*$", RegexOption.IGNORE_CASE) to "PACKER_NAMED_ASSET"
        )
        private val API_USE_RULES = listOf(
            "android.permission.READ_SMS" to listOf("landroid/telephony/smsmessage;", "content://sms"),
            "android.permission.RECEIVE_SMS" to listOf("landroid/telephony/smsmessage;", "android.provider.telephony.sms_received"),
            "android.permission.SEND_SMS" to listOf("smsmanager;->sendtextmessage", "smsmanager;->sendsmsto"),
            "android.permission.READ_CALL_LOG" to listOf("landroid/provider/calllog\$calls;", "content://call_log"),
            "android.permission.WRITE_CALL_LOG" to listOf("landroid/provider/calllog\$calls;", "content://call_log"),
            "android.permission.SYSTEM_ALERT_WINDOW" to listOf("landroid/view/windowmanager;->addview", "action_manage_overlay_permission"),
            "android.permission.REQUEST_INSTALL_PACKAGES" to listOf("action_manage_unknown_app_sources", "landroid/content/pm/packageinstaller;"),
            "android.permission.READ_CONTACTS" to listOf("landroid/provider/contactscontract;", "content://com.android.contacts"),
            "android.permission.READ_PHONE_STATE" to listOf("landroid/telephony/telephonymanager;->getdeviceid", "->getimei", "->getsubscriberid")
        )

        internal fun analyzeObservations(
            requestedPermissions: Set<String>,
            hasAccessibilityService: Boolean,
            deviceAdminReceivers: List<String>,
            components: List<ComponentExposure>,
            debugCertificate: Boolean,
            signerMaterialAvailable: Boolean,
            entryNames: Set<String>,
            dexSamples: List<DeepStaticDexSample>,
            archiveIssues: List<String>,
            signerObservations: List<String> = emptyList()
        ): RiskReport {
            val findings = mutableListOf<RiskFinding>()
            val observations = signerObservations.toMutableList()
            fun add(id: String, severity: RiskSeverity, confidence: Int, evidence: String) {
                findings += RiskFinding(id, severity, evidence, confidence)
            }
            val protectedPermissions = setOf(
                "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
                "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG", "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.READ_CONTACTS", "android.permission.READ_PHONE_STATE"
            )
            val sensitive = requestedPermissions intersect protectedPermissions
            val hasSms = requestedPermissions.any { it in setOf("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS") }
            val hasCallLog = requestedPermissions.any { it in setOf("android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG") }
            val hasInternet = "android.permission.INTERNET" in requestedPermissions
            val hasOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in requestedPermissions

            components.filter { it.exported && !isPermissionProtected(it) }.forEach { component ->
                val severity = if (component.kind == "receiver" || component.kind == "provider" || component.kind == "service") RiskSeverity.MEDIUM else RiskSeverity.LOW
                add(
                    "EXPORTED_${component.kind.uppercase(Locale.ROOT)}_UNPROTECTED", severity, 40,
                    "Exported ${component.kind} ${component.name} has no manifest permission gate visible to this scan; code-level access checks may still exist."
                )
            }
            deviceAdminReceivers.forEach { name ->
                add("DEVICE_ADMIN_RECEIVER_DECLARED", RiskSeverity.LOW, 45, "Declares a Device Administrator receiver: ${name.take(MAX_COMPONENT_NAME_CHARS)}. This is a sensitive capability, not proof of abuse.")
            }
            if (hasAccessibilityService) {
                add("ACCESSIBILITY_SERVICE_DECLARED", RiskSeverity.LOW, 40, "Declares a bound AccessibilityService; legitimate assistive apps may require this capability.")
            }
            if (hasOverlay) add("OVERLAY_PERMISSION_REQUESTED", RiskSeverity.LOW, 35, "Requests SYSTEM_ALERT_WINDOW; overlays can be legitimate but can also obscure UI.")
            if (hasAccessibilityService && (hasOverlay || hasSms || hasCallLog)) {
                add("ACCESSIBILITY_COMBINED_WITH_SENSITIVE_CAPABILITY", RiskSeverity.HIGH, 75, "Combines AccessibilityService with overlay, SMS, or call-log access.")
            }
            if (hasSms && hasCallLog) {
                add("SMS_AND_CALL_LOG_COMBINATION", RiskSeverity.HIGH, 70, "Requests both SMS and call-log permissions.")
            } else if (hasSms && hasInternet) {
                add("SMS_WITH_INTERNET", RiskSeverity.MEDIUM, 55, "Requests SMS access and INTERNET; this combination warrants context review.")
            }
            if (debugCertificate) add("DEBUG_CERTIFICATE", RiskSeverity.MEDIUM, 70, "APK signer looks like an Android debug certificate.")
            if (!signerMaterialAvailable) add("SIGNER_CERTIFICATE_UNAVAILABLE", RiskSeverity.MEDIUM, 65, "Package signing certificate metadata is absent or unreadable.")
            observations += archiveIssues.map { "Archive limitation or anomaly: $it" }
            if (archiveIssues.any { it == "APK_ARCHIVE_UNREADABLE" }) {
                add("APK_ARCHIVE_UNREADABLE", RiskSeverity.LOW, 30, "APK container could not be fully inspected; static archive analysis is incomplete.")
            }
            for (entryName in entryNames) {
                val pattern = PACKER_PATH_PATTERNS.firstOrNull { it.first.matches(entryName) } ?: continue
                add("PACKER_NAME_${pattern.second}", RiskSeverity.LOW, 40, "APK contains a path commonly associated with a packer/protector: ${entryName.take(MAX_ENTRY_NAME_CHARS)}.")
            }
            dexSamples.forEach { sample ->
                val bytes = sample.bytes
                if (bytes.size >= DEX_HEADER_SIZE) {
                    val magicOk = bytes[0] == 'd'.code.toByte() && bytes[1] == 'e'.code.toByte() && bytes[2] == 'x'.code.toByte() && bytes[3] == '\n'.code.toByte() && (4..6).all { bytes[it] in '0'.code.toByte()..'9'.code.toByte() } && bytes[7] == 0.toByte()
                    val declaredSize = ByteBuffer.wrap(bytes, 32, 4).order(ByteOrder.LITTLE_ENDIAN).int.toLong() and 0xffffffffL
                    val headerSize = ByteBuffer.wrap(bytes, 36, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    val endian = ByteBuffer.wrap(bytes, 40, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    if (!magicOk || headerSize != DEX_HEADER_SIZE || endian != DEX_ENDIAN_TAG || declaredSize != bytes.size.toLong()) {
                        add("DEX_HEADER_ANOMALY", RiskSeverity.MEDIUM, 55, "DEX header in ${sample.name} has inconsistent magic/size/endian fields; packed or truncated files are possible, but this is not proof of malware.")
                    }
                } else {
                    add("DEX_HEADER_TRUNCATED", RiskSeverity.MEDIUM, 55, "DEX entry ${sample.name} is shorter than a valid DEX header.")
                }
                if (bytes.size >= MIN_ENTROPY_SAMPLE_BYTES && shannonEntropy(bytes, minOf(bytes.size, MAX_ENTROPY_SAMPLE_BYTES)) >= HIGH_ENTROPY_THRESHOLD) {
                    add("DEX_HIGH_ENTROPY_SAMPLE", RiskSeverity.LOW, 25, "The leading DEX sample has high byte entropy, which may indicate encryption/packing or a benign compressed payload.")
                }
            }
            if (dexSamples.isNotEmpty() && archiveIssues.none { it.contains("DEX_SIZE_LIMIT") || it == "DEX_TOTAL_SIZE_LIMIT" }) {
                val mismatches = sensitive.filter { permission ->
                    val markers = API_USE_RULES.firstOrNull { it.first == permission }?.second ?: return@filter false
                    markers.all { marker -> dexSamples.none { sample -> containsAsciiIgnoreCase(sample.bytes, marker) } }
                }
                if (mismatches.isNotEmpty()) {
                    add("REQUESTED_PERMISSION_API_REFERENCE_MISMATCH", RiskSeverity.LOW, 25, "No known static DEX string reference was found for requested permission(s): ${mismatches.joinToString()}. Reflection, native calls, libraries or dynamic code may explain the absence.")
                }
            }
            val score = findings.sumOf { finding ->
                val weight = when (finding.severity) { RiskSeverity.LOW -> 8; RiskSeverity.MEDIUM -> 18; RiskSeverity.HIGH -> 30 }
                (weight * finding.confidence / 100.0).toInt()
            }.coerceAtMost(100)
            return RiskReport(findings.distinctBy { it.ruleId + it.evidence }, score, observations.distinct())
        }

        private data class InternalDexSample(val name: String, val bytes: ByteArray)
        private const val DEX_HEADER_SIZE = 0x70
        private const val DEX_ENDIAN_TAG = 0x12345678
        private const val MIN_ENTROPY_SAMPLE_BYTES = 64 * 1024
        private const val MAX_ENTROPY_SAMPLE_BYTES = 128 * 1024
        private const val HIGH_ENTROPY_THRESHOLD = 7.45

        private fun isPermissionProtected(component: ComponentExposure): Boolean =
            !component.permission.isNullOrBlank() || !component.readPermission.isNullOrBlank() || !component.writePermission.isNullOrBlank()

        private fun containsAsciiIgnoreCase(bytes: ByteArray, token: String): Boolean {
            val needle = token.toByteArray(Charsets.US_ASCII)
            if (needle.isEmpty() || needle.size > bytes.size) return false
            val last = bytes.size - needle.size
            for (start in 0..last) {
                if (lowerAscii(bytes[start]) != needle[0]) continue
                var offset = 1
                while (offset < needle.size && lowerAscii(bytes[start + offset]) == needle[offset]) offset++
                if (offset == needle.size) return true
            }
            return false
        }

        private fun lowerAscii(value: Byte): Byte {
            val unsigned = value.toInt() and 0xff
            return (if (unsigned in 65..90) unsigned + 32 else unsigned).toByte()
        }

        private fun shannonEntropy(bytes: ByteArray, sampleSize: Int): Double {
            if (sampleSize <= 0) return 0.0
            val counts = IntArray(256)
            for (i in 0 until sampleSize) counts[bytes[i].toInt() and 0xff]++
            var entropy = 0.0
            for (count in counts) if (count > 0) {
                val p = count.toDouble() / sampleSize
                entropy -= p * (ln(p) / ln(2.0))
            }
            return entropy
        }
    }
}