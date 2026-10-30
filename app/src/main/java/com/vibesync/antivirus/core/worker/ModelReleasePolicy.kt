package com.vibesync.antivirus.core.worker

import org.json.JSONObject

/** Research update channel: versioning and bundle integrity, never production ML approval. */
internal object ModelReleasePolicy {
    const val MODEL = "malware_model.tflite"
    const val SCHEMA = "feature_schema.json"
    const val REPORT = "model_report.json"
    const val NOTICE = "DATASET_NOTICE.md"
    const val SUMS = "SHA256SUMS"
    const val FEATURES = 215
    const val MAX_BYTES = 20 * 1024 * 1024
    private val pattern = Regex("^v([0-9]{1,6})\\.([0-9]{1,6})\\.([0-9]{1,6})-model$")

    fun version(tag: String): List<Int>? = pattern.matchEntire(tag)?.groupValues?.drop(1)?.map { it.toInt() }
    fun isNewer(next: String, current: String?): Boolean {
        val a = version(next) ?: return false
        val b = current?.let(::version) ?: return true
        for (i in 0..2) if (a[i] != b[i]) return a[i] > b[i]
        return false
    }
    fun assets(release: JSONObject): Map<String, JSONObject>? {
        if (release.optBoolean("draft", true) || version(release.optString("tag_name")) == null) return null
        val array = release.optJSONArray("assets") ?: return null
        val names = setOf(MODEL, SCHEMA, REPORT, NOTICE, SUMS)
        val found = mutableMapOf<String, JSONObject>()
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val name = item.optString("name")
            if (name in names && found.put(name, item) != null) return null
        }
        return found.takeIf { it.keys == names }
    }
    fun checksums(text: String): Map<String, String>? {
        val required = setOf(MODEL, SCHEMA, REPORT, NOTICE)
        val names = required + ThreatIntelligenceStats.FILE_NAME
        val pattern = Regex("^([0-9a-f]{64})  ([A-Za-z0-9_.-]+)$")
        val result = mutableMapOf<String, String>()
        for (line in text.trim().lines()) {
            val match = pattern.matchEntire(line) ?: return null
            if (match.groupValues[2] !in names ||
                result.put(match.groupValues[2], match.groupValues[1]) != null) return null
        }
        return result.takeIf { it.keys.containsAll(required) }
    }
    /** Stats are optional on older releases; duplicates are not an authoritative snapshot. */
    fun statisticsAsset(release: JSONObject): JSONObject? {
        if (release.optBoolean("draft", true) || version(release.optString("tag_name")) == null) return null
        val assets = release.optJSONArray("assets") ?: return null
        val found = (0 until assets.length()).mapNotNull { assets.optJSONObject(it) }
            .filter { it.optString("name") == ThreatIntelligenceStats.FILE_NAME }
        return found.singleOrNull()
    }
    fun validatedResearchBundle(schema: JSONObject, report: JSONObject, modelSha: String, schemaSha: String): Boolean {
        if (report.optBoolean("is_synthetic", true) || report.optInt("feature_count") != FEATURES ||
            report.optString("feature_schema_sha256") != schemaSha) return false
        val model = report.optJSONObject("tflite") ?: return false
        if (model.optString("sha256") != modelSha || model.optString("input_dtype") != "float32" ||
            model.optString("output_dtype") != "float32") return false
        val shapeIn = model.optJSONArray("input_shape") ?: return false
        val shapeOut = model.optJSONArray("output_shape") ?: return false
        if (shapeIn.length() != 2 || shapeIn.optInt(0) != 1 || shapeIn.optInt(1) != FEATURES ||
            shapeOut.length() != 2 || shapeOut.optInt(0) != 1 || shapeOut.optInt(1) != 1) return false
        val names = report.optJSONArray("feature_names") ?: return false
        if (schema.length() != FEATURES || names.length() != FEATURES) return false
        return (0 until FEATURES).all { i ->
            val name = names.optString(i)
            name.isNotBlank() && schema.optString(i.toString()) == name
        }
    }
}
