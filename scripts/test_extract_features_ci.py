"""Offline, network-free tests for TweetFeed-to-local-APK feature extraction."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from extract_features_ci import (
    SampleRejected, analyze_android_apk, feature_vector, recent_tweetfeed_sha256_iocs,
    schema_features, extract_recent, file_sha256, has_complete_reputation,
)
from prepare_feature_batches_ci import create_batches


class StaticFeatureTests(unittest.TestCase):
    def test_real_215_schema_frozen_and_contiguous(self):
        names = schema_features()
        self.assertEqual(len(names), 215)
        self.assertEqual(names[0], "transact")
        self.assertEqual(names[6], "SEND_SMS")
        self.assertEqual(names[214], "WRITE_SECURE_SETTINGS")

    def test_vector_matches_android_style_permission_call_and_action(self):
        names = schema_features()
        vector = feature_vector(
            names,
            permissions={"android.permission.SEND_SMS", "android.permission.READ_PHONE_STATE"},
            actions={"android.intent.action.BOOT_COMPLETED"},
            classes={"Ldalvik/system/DexClassLoader;"},
            calls={("Ljava/lang/Class;", "getCanonicalName")},
            callbacks={"onServiceConnected"},
            literals={"chmod /system/bin/sh"},
        )
        self.assertEqual(len(vector), 215)
        for idx in (1, 6, 7, 13, 25):
            self.assertEqual(vector[idx], 1, f"feature index {idx}")
        self.assertEqual(vector[0], 0)
        self.assertTrue(all(bit in (0, 1) for bit in vector))

    def test_nonmatching_substrings_do_not_set_features(self):
        names = schema_features()
        vector = feature_vector(
            names,
            permissions={"vendor.permission.SEND_SMS"},
            actions={"android.intent.action.BOOT_COMPLETED_FAKE"},
            classes={"Ldalvik/system/DexClassLoaderExtra;"},
            calls={("Lvendor/some/Class;", "getCanonicalName")},
            literals={"dischmodfix"},
        )
        for idx in (6, 7, 25):
            self.assertEqual(vector[idx], 0)


class TweetFeedLocalSampleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_tweetfeed(self, digest: str):
        recent = self.root / "tweetfeed.json"
        recent.write_text(json.dumps([
            {"type": "domain", "value": "malicious.example"},
            {"type": "sha256", "value": digest},
            {"type": "sha256", "value": digest.upper()},
            {"type": "url", "value": "https://example.invalid/payload"},
        ]))
        return recent

    def test_parser_only_reads_sha256_hash_ioc_field(self):
        digest = "a" * 64
        recent = self.write_tweetfeed(digest)
        self.assertEqual(recent_tweetfeed_sha256_iocs(recent), [digest])

    def test_parser_rejects_non_ok_or_malformed_sha256_data(self):
        recent = self.root / "bad.json"
        recent.write_text(json.dumps({"error": "not an array"}))
        with self.assertRaises(ValueError):
            recent_tweetfeed_sha256_iocs(recent)
        recent.write_text(json.dumps([
            {"type": "sha256", "value": "not-a-sha256"}
        ]))
        with self.assertRaisesRegex(ValueError, "malformed"):
            recent_tweetfeed_sha256_iocs(recent)

    def test_written_ai_training_permission_is_required(self):
        digest = hashlib.sha256(b"APK bytes staged by a separately authorized source").hexdigest()
        recent = self.write_tweetfeed(digest)
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(PermissionError, "separate APK sample source"):
                extract_recent(recent, self.root / "rows.json", 10, samples_dir=self.root / "samples")

    def test_no_sample_binaries_means_no_fabricated_feature_rows(self):
        digest = hashlib.sha256(b"APK bytes").hexdigest()
        recent = self.write_tweetfeed(digest)
        samples_dir = self.root / "missing-samples"
        output = self.root / "rows.json"
        reputation = {
            "vt_malicious_count": "-1",
            "ha_threat_score": "88",
            "ha_verdict": "suspicious",
        }
        with (
            patch.dict("os.environ", {"LOCAL_APK_TRAINING_APPROVED": "true"}),
            patch("extract_features_ci.load_enrichment_cache", return_value={digest: reputation}),
        ):
            rows = extract_recent(recent, output, 10, samples_dir=samples_dir)
        self.assertEqual(rows, [])
        payload = json.loads(output.read_text())
        self.assertEqual(payload, {"feature_rows": [], "feature_metadata": []})

    def test_feature_extraction_uses_local_hash_matching_apk(self):
        apk_bytes = b"APK bytes staged by a separately authorized source"
        digest = hashlib.sha256(apk_bytes).hexdigest()
        recent = self.write_tweetfeed(digest)
        samples = self.root / "samples"
        samples.mkdir()
        (samples / f"{digest}.apk").write_bytes(apk_bytes)
        output = self.root / "rows.json"
        reputation = {
            "vt_malicious_count": "-1",
            "ha_threat_score": "88",
            "ha_verdict": "suspicious",
        }
        with (
            patch.dict("os.environ", {"LOCAL_APK_TRAINING_APPROVED": "true"}),
            patch("extract_features_ci.load_enrichment_cache", return_value={digest: reputation}),
            patch("extract_features_ci.analyze_android_apk", return_value=[1] * 215),
        ):
            rows = extract_recent(recent, output, 10, samples_dir=samples)
        self.assertEqual(rows, [[1] * 215])
        payload = json.loads(output.read_text())
        self.assertEqual(len(payload["feature_rows"][0]), 215)
        self.assertEqual(payload["feature_metadata"][0]["sha256"], digest)
        self.assertEqual(payload["feature_metadata"][0]["vt_malicious_count"], -1)
        self.assertNotIn(apk_bytes.decode(), output.read_text())
        self.assertEqual(file_sha256(samples / f"{digest}.apk"), digest)

    def test_hash_mismatch_or_unqualified_reputation_is_skipped(self):
        good_bytes = b"correct local APK"
        digest = hashlib.sha256(good_bytes).hexdigest()
        wrong_digest = hashlib.sha256(b"wrong APK").hexdigest()
        recent = self.root / "tweetfeed.json"
        recent.write_text(json.dumps([
            {"type": "sha256", "value": digest},
            {"type": "sha256", "value": wrong_digest},
        ]))
        samples = self.root / "samples"
        samples.mkdir()
        (samples / f"{digest}.apk").write_bytes(b"mismatch")
        (samples / f"{wrong_digest}.apk").write_bytes(b"wrong APK")
        output = self.root / "rows.json"
        reputation = {
            digest: {"vt_malicious_count": "-1", "ha_threat_score": "88", "ha_verdict": "suspicious"},
            wrong_digest: {"vt_malicious_count": "-1", "ha_threat_score": "20", "ha_verdict": "suspicious"},
        }
        with (
            patch.dict("os.environ", {"LOCAL_APK_TRAINING_APPROVED": "true"}),
            patch("extract_features_ci.load_enrichment_cache", return_value=reputation),
            patch("extract_features_ci.analyze_android_apk", return_value=[1] * 215),
        ):
            rows = extract_recent(recent, output, 10, samples_dir=samples)
        self.assertEqual(rows, [])

    def test_vt_disabled_ha_threshold_or_verdict_forwarding_rule(self):
        self.assertTrue(has_complete_reputation({
            "vt_malicious_count": "-1", "ha_threat_score": "70", "ha_verdict": "suspicious"
        }))
        self.assertTrue(has_complete_reputation({
            "vt_malicious_count": "-1", "ha_threat_score": "24", "ha_verdict": "malicious"
        }))
        self.assertTrue(has_complete_reputation({
            "vt_malicious_count": "-1", "ha_threat_score": "Not Found", "ha_verdict": "malicious"
        }))
        self.assertFalse(has_complete_reputation({
            "vt_malicious_count": "-1", "ha_threat_score": "69.9", "ha_verdict": "suspicious"
        }))
        self.assertFalse(has_complete_reputation({
            "vt_malicious_count": "0", "ha_threat_score": "90", "ha_verdict": "suspicious"
        }))


class BatchAndNetworkSafetyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_dispatch_carries_aligned_reputation_sidecar_and_keeps_215_bit_shape(self):
        raw = self.root / "metadata.json"
        metadata = [{"sha256": "a" * 64, "vt_malicious_count": -1,
                     "ha_threat_score": 93.0, "ha_verdict": "suspicious"} for _ in range(12)]
        raw.write_text(json.dumps({"feature_rows": [[1] * 215 for _ in range(12)],
                                   "feature_metadata": metadata}))
        batches = create_batches(raw, self.root / "metadata-dispatch")
        self.assertEqual(len(batches), 2)
        for batch in batches:
            payload = json.loads(batch.read_text())["client_payload"]
            self.assertEqual(len(payload["feature_rows"][0]), 215)
            self.assertEqual(len(payload["metadata"]), len(payload["feature_rows"]))
            self.assertEqual(payload["metadata"][0]["vt_malicious_count"], -1)

    def test_dispatch_exact_shape_ten_rows_and_empty_no_http(self):
        raw = self.root / "data.json"
        raw.write_text(json.dumps({"feature_rows": [[i % 2] * 215 for i in range(20)]}))
        batches = create_batches(raw, self.root / "dispatch")
        self.assertEqual(len(batches), 2)
        for batch in batches:
            obj = json.loads(batch.read_text())
            self.assertEqual(obj["event_type"], "new_malware_features")
            self.assertEqual(set(obj["client_payload"]), {"feature_rows"})
            self.assertEqual(len(obj["client_payload"]["feature_rows"]), 10)
        blank = self.root / "empty.json"
        blank.write_text(json.dumps({"feature_rows": []}))
        self.assertEqual(create_batches(blank, self.root / "empty"), [])

    def test_reject_invalid_rows_before_creating_dispatch(self):
        path = self.root / "bad.json"
        for rows in ([[0] * 214], [[True] * 215], [[2] * 215], [[0] * 215] * 21):
            with self.subTest(rows=repr(rows)[:30]):
                path.write_text(json.dumps({"feature_rows": rows}))
                with self.assertRaises(ValueError):
                    create_batches(path, self.root / "not-created")


if __name__ == "__main__":
    unittest.main()
