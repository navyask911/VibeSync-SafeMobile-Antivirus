"""Offline CI checks: preserve disabled dummy while preparing the 215-input schema."""
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
KOTLIN = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/MachineLearningScanner.kt"
EXTRACTOR = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/DrebinFeatureContract.kt"
SCRIPT = Path(__file__).with_name("train_ml_model.py")
KNOWN_SCHEMA_SHA256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"

class MLFixtureContractTest(unittest.TestCase):
    def test_bundled_dummy_stays_untrained_and_off(self):
        spec = importlib.util.spec_from_file_location("safe_mobile_training", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(len(module.FEATURES), 32)
        self.assertEqual(len(set(module.FEATURES)), 32)
        manifest = json.loads((ASSETS / "malware_model.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["features"], module.FEATURES)
        self.assertEqual(manifest["feature_count"], 32)
        self.assertFalse(manifest["validated"])
        self.assertFalse(manifest["trained"])
        self.assertEqual(manifest["status"], "dummy_untrained")
        kotlin = KOTLIN.read_text(encoding="utf-8")
        self.assertIn('metadata.optBoolean("production_ready")', kotlin)
        self.assertIn('metadata.optString("status") != "validated_production"', kotlin)
        self.assertIn('DrebinFeatureContract.loadSchema', kotlin)
        self.assertNotIn('private val FEATURES = listOf(', kotlin)

    def test_frozen_research_schema_is_ordered_and_pinned(self):
        raw = (ASSETS / "feature_schema.json").read_bytes()
        schema = json.loads(raw)
        self.assertEqual(len(schema), 215)
        self.assertEqual(list(schema.keys()), [str(i) for i in range(215)])
        self.assertEqual(len(set(schema.values())), 215)
        self.assertEqual(schema["0"], "transact")
        self.assertEqual(schema["6"], "SEND_SMS")
        self.assertEqual(schema["214"], "WRITE_SECURE_SETTINGS")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), KNOWN_SCHEMA_SHA256)
        extractor = EXTRACTOR.read_text(encoding="utf-8")
        self.assertIn('const val COUNT = 215', extractor)
        self.assertIn('FloatArray(COUNT)', extractor)

    def test_tflite_fixture_identifier_and_size(self):
        data = (ASSETS / "malware_model.tflite").read_bytes()
        self.assertEqual(data[4:8], b"TFL3")
        self.assertGreater(len(data), 64)
        self.assertLess(len(data), 50 * 1024 * 1024)

if __name__ == "__main__":
    unittest.main()
