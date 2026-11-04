"""Offline contract tests for the SHA-pinned, build-time downloaded Drebin-215 research assets."""
import hashlib
import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
GRADLE = ROOT / "app/build.gradle.kts"
IGNORE = ROOT / ".gitignore"
INFERENCE = ROOT / "app/src/main/java/com/vibesync/antivirus/engine/ml/TfliteInferenceEngine.kt"
SCANNER = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/MachineLearningScanner.kt"
CONTRACT = ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/DrebinFeatureContract.kt"
KNOWN_SCHEMA_SHA256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
KNOWN_MODEL_SHA256 = "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"


class ResearchModelContractTests(unittest.TestCase):
    def test_downloaded_model_is_the_approved_tflite_release_asset(self):
        model = (ASSETS / "model.tflite").read_bytes()
        self.assertEqual(len(model), 18584)
        self.assertEqual(hashlib.sha256(model).hexdigest(), KNOWN_MODEL_SHA256)
        self.assertEqual(model[4:8], b"TFL3")
        inference = INFERENCE.read_text(encoding="utf-8")
        scanner = SCANNER.read_text(encoding="utf-8")
        self.assertIn('MODEL_ASSET_NAME = "model.tflite"', inference)
        self.assertIn('MODEL_ASSET_NAME = "model.tflite"', scanner)
        self.assertIn("MODEL_PRODUCTION_READY = false", scanner)
        self.assertIn("MODEL_VALIDATED = false", scanner)
        self.assertIn('MODEL_STATUS = "research_candidate"', scanner)

    def test_downloaded_schema_is_exact_ordered_215_feature_contract(self):
        raw = (ASSETS / "feature_schema.json").read_bytes()
        schema = json.loads(raw)
        self.assertEqual(list(schema.keys()), [str(i) for i in range(215)])
        self.assertEqual(len(set(schema.values())), 215)
        self.assertEqual(schema["0"], "transact")
        self.assertEqual(schema["6"], "SEND_SMS")
        self.assertEqual(schema["214"], "WRITE_SECURE_SETTINGS")
        self.assertEqual(hashlib.sha256(raw).hexdigest(), KNOWN_SCHEMA_SHA256)
        contract = CONTRACT.read_text(encoding="utf-8")
        self.assertIn("const val COUNT = 215", contract)
        self.assertIn('assets.open("feature_schema.json")', contract)

    def test_gradle_bridge_downloads_and_verifies_immutable_release_before_prebuild(self):
        gradle = GRADLE.read_text(encoding="utf-8")
        self.assertIn('tasks.register("downloadMlAssets")', gradle)
        self.assertIn("tasks.named(\"preBuild\").configure", gradle)
        self.assertIn("dependsOn(downloadMlAssets)", gradle)
        self.assertIn(
            "releases/download/v1.0.1-model/malware_model.tflite", gradle
        )
        self.assertIn(
            "releases/download/v1.0.1-model/feature_schema.json", gradle
        )
        self.assertIn(KNOWN_MODEL_SHA256, gradle)
        self.assertIn(KNOWN_SCHEMA_SHA256, gradle)
        self.assertIn('model.tflite', gradle)

    def test_model_and_schema_downloads_are_git_ignored_and_untracked(self):
        ignore = IGNORE.read_text(encoding="utf-8")
        for path in (
            "/app/src/main/assets/model.tflite",
            "/app/src/main/assets/malware_model.tflite",
            "/app/src/main/assets/feature_schema.json",
            "/app/src/main/assets/malware_model.json",
        ):
            self.assertIn(path, ignore)
        tracked = subprocess.run(
            ["git", "ls-files"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.splitlines()
        forbidden = {
            "app/src/main/assets/model.tflite",
            "app/src/main/assets/malware_model.tflite",
            "app/src/main/assets/feature_schema.json",
            "app/src/main/assets/malware_model.json",
        }
        self.assertTrue(forbidden.isdisjoint(set(tracked)))


if __name__ == "__main__":
    unittest.main()
