package com.vibesync.antivirus.core.worker

import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

class ModelReleasePolicyTest {
    @Test fun versionsCompareNumericallyAndRejectUnexpectedTags() {
        assertTrue(ModelReleasePolicy.isNewer("v1.0.10-model", "v1.0.9-model"))
        assertTrue(ModelReleasePolicy.isNewer("v1.0.0-model", null))
        assertFalse(ModelReleasePolicy.isNewer("v1.0.1-model", "v1.0.1-model"))
        assertFalse(ModelReleasePolicy.isNewer("v1.0.2-model", "v1.1.0-model"))
        assertFalse(ModelReleasePolicy.isNewer("random", null))
        assertFalse(ModelReleasePolicy.isNewer("v1.0.1-model-test", null))
    }

    @Test fun checksumsMustContainEveryArtifactOnce() {
        val names = listOf("malware_model.tflite", "feature_schema.json",
            "model_report.json", "DATASET_NOTICE.md")
        val data = names.joinToString("\n") { "a".repeat(64) + "  " + it }
        assertEquals(4, ModelReleasePolicy.checksums(data)!!.size)
        assertNull(ModelReleasePolicy.checksums(data + "\n" + "a".repeat(64) + "  malware_model.tflite"))
        assertNull(ModelReleasePolicy.checksums(data.replace("  feature_schema.json", "  evil.bin")))
    }

    @Test fun releaseMustContainAllAssetsAndCorrectTag() {
        val names = listOf("malware_model.tflite", "feature_schema.json", "model_report.json",
            "DATASET_NOTICE.md", "SHA256SUMS")
        val assets = JSONArray()
        names.forEach { name -> assets.put(JSONObject().put("name", name)) }
        val release = JSONObject().put("draft", false).put("tag_name", "v1.0.0-model")
            .put("assets", assets)
        assertEquals(5, ModelReleasePolicy.assets(release)!!.size)
        assertNull(ModelReleasePolicy.assets(release.put("draft", true)))
    }

    @Test fun researchMetadataNeverAcceptsSyntheticOrMismatchedShapes() {
        val schema = JSONObject()
        val features = JSONArray()
        repeat(215) {
            schema.put(it.toString(), "feature-" + it)
            features.put("feature-" + it)
        }
        val input = JSONArray().put(1).put(215)
        val output = JSONArray().put(1).put(1)
        val model = JSONObject().put("sha256", "b".repeat(64))
            .put("input_shape", input).put("output_shape", output)
            .put("input_dtype", "float32").put("output_dtype", "float32")
        val report = JSONObject().put("is_synthetic", false)
            .put("feature_count", 215)
            .put("feature_names", features).put("feature_schema_sha256", "c".repeat(64))
            .put("tflite", model).put("production_ready", false)
        assertTrue(ModelReleasePolicy.validatedResearchBundle(schema, report, "b".repeat(64), "c".repeat(64)))
        report.put("is_synthetic", true)
        assertFalse(ModelReleasePolicy.validatedResearchBundle(schema, report, "b".repeat(64), "c".repeat(64)))
        report.put("is_synthetic", false)
        model.put("input_shape", JSONArray().put(1).put(32))
        assertFalse(ModelReleasePolicy.validatedResearchBundle(schema, report, "b".repeat(64), "c".repeat(64)))
    }
}
