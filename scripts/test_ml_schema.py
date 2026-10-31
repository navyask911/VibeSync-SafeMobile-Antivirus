"""Offline tests of the SHA-256-pinned, 215-feature Drebin research activation boundary."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
KOTLIN = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/MachineLearningScanner.kt"
EXTRACTOR = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/DrebinFeatureContract.kt"
GRADLE = ROOT / "app/build.gradle.kts"
KNOWN_SCHEMA_SHA256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
KNOWN_MODEL_SHA256 = "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"

class ResearchModelContractTests(unittest.TestCase):
    def test_metadata_matches_exact_215_feature_training_schema(self):
        schema=json.loads((ASSETS/"feature_schema.json").read_text(encoding="utf-8"))
        metadata=json.loads((ASSETS/"malware_model.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["feature_count"], 215)
        self.assertEqual(metadata["features"], [schema[str(i)] for i in range(215)])
        self.assertTrue(metadata["trained"])
        self.assertFalse(metadata["dummy_untrained"])
        self.assertFalse(metadata["validated"])
        self.assertFalse(metadata["production_ready"])
        self.assertEqual(metadata["status"], "research_candidate")
        self.assertEqual(metadata["model_sha256"], KNOWN_MODEL_SHA256)
        kotlin=KOTLIN.read_text(encoding="utf-8")
        self.assertIn('metadata.optBoolean("production_ready")', kotlin)
        self.assertIn('metadata.optString("status") == "validated_production"', kotlin)
        self.assertIn('metadata.optString("status") == "research_candidate"', kotlin)
        self.assertIn('DrebinFeatureContract.loadSchema', kotlin)
        self.assertNotIn('private val FEATURES = listOf(', kotlin)

    def test_feature_schema_is_ordered_and_pinned(self):
        raw=(ASSETS/"feature_schema.json").read_bytes()
        schema=json.loads(raw)
        self.assertEqual(list(schema.keys()), [str(i) for i in range(215)])
        self.assertEqual(len(set(schema.values())), 215)
        self.assertEqual(schema["0"], "transact")
        self.assertEqual(schema["6"], "SEND_SMS")
        self.assertEqual(schema["214"], "WRITE_SECURE_SETTINGS")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), KNOWN_SCHEMA_SHA256)
        extractor=EXTRACTOR.read_text(encoding="utf-8")
        self.assertIn('const val COUNT = 215', extractor)
        self.assertIn('FloatArray(COUNT)', extractor)

    def test_no_legacy_model_in_source_and_release_is_sha_pinned(self):
        self.assertFalse((ASSETS/"malware_model.tflite").exists())
        gradle=GRADLE.read_text(encoding="utf-8")
        self.assertIn("stageResearchModel",gradle)
        self.assertIn(KNOWN_MODEL_SHA256,gradle)
        self.assertIn(KNOWN_SCHEMA_SHA256,gradle)
        self.assertIn("18584",gradle)
        self.assertIn('String(bytes, 4, 4, Charsets.US_ASCII) == "TFL3"',gradle)

if __name__ == "__main__":
    unittest.main()
