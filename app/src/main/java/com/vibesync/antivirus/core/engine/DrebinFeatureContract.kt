package com.vibesync.antivirus.core.engine

import android.content.res.AssetManager
import org.json.JSONObject

/** Exact order and matching rules from the separate Drebin-215 training feature extractor.
 * A vector alone is NOT a trained or validated malware verdict.
 */
internal object DrebinFeatureContract {
    const val COUNT = 215
    private val classFeatures = setOf(
        "ServiceConnection", "ClassLoader", "DexClassLoader", "SecretKey", "KeySpec",
        "Binder", "IBinder", "URLClassLoader", "PathClassLoader", "PackageInstaller",
        "HttpUriRequest", "MessengerService", "IRemoteService", "ProcessBuilder",
        "android.os.Binder", "android.os.IBinder", "android.content.pm.Signature",
        "android.telephony.SmsManager", "android.telephony.gsm.SmsManager",
        "android.content.pm.PackageInfo", "Ljava.net.URLDecoder",
        "Ljavax.crypto.spec.SecretKeySpec", "Ljavax.crypto.Cipher"
    )
    private val callbackNames = setOf("onBind", "onServiceConnected")
    private val commandNames = setOf("mount", "remount", "chmod", "chown")
    private val word = Regex("[A-Za-z0-9_]")

    data class Observed(
        val permissions: Set<String>,
        val actions: Set<String>,
        val classes: Set<String>,
        val calls: Set<Pair<String, String>>,
        val callbacks: Set<String>,
        val literals: Set<String>
    )

    fun loadSchema(assets: AssetManager): List<String>? = runCatching {
        val bytes = assets.open("feature_schema.json").use { input ->
            input.readBytes().takeIf { it.size in 100..32768 } ?: error("Invalid schema size")
        }
        val dictionary = JSONObject(String(bytes, Charsets.UTF_8))
        require(dictionary.length() == COUNT)
        List(COUNT) { index ->
            val key = index.toString()
            require(dictionary.has(key))
            dictionary.getString(key).also { require(it.isNotBlank()) }
        }.also { require(it.distinct().size == COUNT) }
    }.getOrNull()

    fun vector(schema: List<String>, observed: Observed): FloatArray {
        require(schema.size == COUNT && schema.distinct().size == COUNT)
        val permissions = observed.permissions.mapNotNull { full ->
            when {
                full.startsWith("android.permission.") -> full.removePrefix("android.permission.")
                full.startsWith("com.android.browser.permission.") -> full.removePrefix("com.android.browser.permission.")
                else -> null
            }
        }.toSet()
        val classes = observed.classes.map(::normalizeClass).toSet()
        val simple = classes.map { it.substringAfterLast('.') }.toSet()
        val calls = buildSet {
            for ((owner, invoked) in observed.calls) {
                val type = normalizeClass(owner)
                val method = if (invoked == "<init>") "init" else invoked
                add(method)
                add(type + "." + method)
                add(type.substringAfterLast('.') + "." + method)
            }
        }
        return FloatArray(COUNT) { index ->
            val feature = schema[index]
            val found = when {
                feature.isNotBlank() && feature.all { it.isUpperCase() || it.isDigit() || it == '_' } ->
                    feature in permissions
                "intent.action." in feature ->
                    feature in observed.actions ||
                        (feature == "intent.action.RUN" && "android.intent.action.RUN" in observed.actions)
                feature in classFeatures -> {
                    val normalized = normalizeClass(feature)
                    normalized in classes || ('.' !in normalized && normalized in simple)
                }
                feature in commandNames -> observed.literals.any { containsWord(it, feature) }
                feature.startsWith("/system/") -> observed.literals.any { value ->
                    Regex(Regex.escape(feature) + "(?=/|$|\\s)").containsMatchIn(value)
                }
                else -> {
                    val method = normalizeLegacy(feature)
                    method in calls || (feature in callbackNames && feature in observed.callbacks)
                }
            }
            if (found) 1f else 0f
        }
    }

    private fun containsWord(text: String, token: String): Boolean {
        var at = text.indexOf(token)
        while (at >= 0) {
            val left = at == 0 || !word.matches(text[at - 1].toString())
            val right = at + token.length == text.length ||
                !word.matches(text[at + token.length].toString())
            if (left && right) return true
            at = text.indexOf(token, at + 1)
        }
        return false
    }

    private fun normalizeLegacy(input: String) =
        if (input.startsWith("Ljava.") || input.startsWith("Ljavax.") ||
            input.startsWith("Landroid.")) input.drop(1) else input

    private fun normalizeClass(input: String): String {
        val trimmed = input.trimStart('[').removePrefix("L").removeSuffix(";")
        return trimmed.replace('/', '.')
    }
}
