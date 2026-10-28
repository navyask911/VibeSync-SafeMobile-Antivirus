"""Offline CI checks: never train or download malware datasets."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
KOTLIN = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/MachineLearningScanner.kt"
SCRIPT = Path(__file__).with_name("train_ml_model.py")

class MLFixtureContractTest(unittest.TestCase):
    def test_feature_contract_and_dummy_gate(self):
        spec = importlib.util.spec_from_file_location("safe_mobile_training", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(len(module.FEATURES), 32)
        self.assertEqual(len(set(module.FEATURES)), 32)
        kotlin = KOTLIN.read_text(encoding="utf-8")
        for name in module.FEATURES:
            self.assertIn('"' + name + '"', kotlin)
        manifest = json.loads((ASSETS / "malware_model.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["features"], module.FEATURES)
        self.assertEqual(manifest["feature_count"], 32)
        self.assertFalse(manifest["validated"])
        self.assertFalse(manifest["trained"])
        self.assertEqual(manifest["status"], "dummy_untrained")

    def test_tflite_fixture_identifier_and_size(self):
        data = (ASSETS / "malware_model.tflite").read_bytes()
        self.assertEqual(data[4:8], b"TFL3")
        self.assertGreater(len(data), 64)
        self.assertLess(len(data), 50 * 1024 * 1024)

if __name__ == "__main__":
    unittest.main()
