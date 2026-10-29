"""Malware-free, network-free CI tests for the optional MLOps dispatch bridge."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from extract_features_ci import (
    SCHEMA_PATH, SampleRejected, feature_vector, recent_apk_digests, schema_features,
    extract_recent, MAX_APK_BYTES,
)
from prepare_feature_batches_ci import create_batches


class StaticFeatureTests(unittest.TestCase):
    def test_real_215_schema_frozen_and_contiguous(self):
        names = schema_features(SCHEMA_PATH)
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

    def test_unknown_schema_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "schema.json"
            p.write_text(json.dumps({str(i): f"x_{i}" for i in range(215)}))
            with self.assertRaisesRegex(ValueError, "Pinned feature schema mismatch"):
                schema_features(p)


class BatchAndNetworkSafetyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_recent_filter_deduplicates_only_android_candidates(self):
        digest = "a" * 64
        other = "b" * 64
        records = {
            "query_status": "ok",
            "data": [
                {"sha256_hash": digest, "file_name": "sample.apk"},
                {"sha256_hash": digest, "file_name": "sample.apk"},
                {"sha256_hash": "c" * 64, "file_name": "evil.exe"},
                {"sha256_hash": other, "file_type": "apk"},
                {"sha256_hash": "../not-a-digest", "file_name": "x.apk"},
            ],
        }
        p = self.root / "recent.json"
        p.write_text(json.dumps(records))
        self.assertEqual(recent_apk_digests(p), [digest, other])

    def test_corrupt_one_sample_does_not_block_next_and_no_raw_binary_in_output(self):
        recent = self.root / "recent.json"
        recent.write_text(json.dumps({"query_status": "ok", "data": [
            {"sha256_hash": "a" * 64, "file_type": "apk"},
            {"sha256_hash": "b" * 64, "file_type": "apk"},
        ]}))
        out = self.root / "vectors.json"
        with patch.dict("os.environ", {"MALWAREBAZAAR_AUTH_KEY": "test-only"}), (
                patch("extract_features_ci.download_sample", side_effect=[SampleRejected("corrupt"), b"mock_zip"])), (
                patch("extract_features_ci.encrypted_zip_to_apk", return_value=b"mock_apk")), (
                patch("extract_features_ci.analyze_android_apk", return_value=[1] * 215)):
            result = extract_recent(recent, out, 10, session=Mock())
        self.assertEqual(len(result), 1)
        self.assertEqual(json.loads(out.read_text()), {"feature_rows": [[1] * 215]})
        self.assertNotIn("mock_apk", out.read_text())
        self.assertFalse(any(self.root.glob("*.apk")))
        self.assertLess(MAX_APK_BYTES, 30 * 1024 * 1024)

    def test_dispatch_exact_shape_ten_rows_and_empty_no_http(self):
        raw = self.root / "data.json"
        raw.write_text(json.dumps({"feature_rows": [[i % 2] * 215 for i in range(20)]}))
        batches = create_batches(raw, self.root / "dispatch")
        self.assertEqual(len(batches), 2)
        for p in batches:
            obj = json.loads(p.read_text())
            self.assertEqual(obj["event_type"], "new_malware_features")
            self.assertEqual(set(obj["client_payload"]), {"feature_rows"})
            self.assertEqual(len(obj["client_payload"]["feature_rows"]), 10)
        blank = self.root / "empty.json"
        blank.write_text(json.dumps({"feature_rows": []}))
        self.assertEqual(create_batches(blank, self.root / "empty"), [])

    def test_reject_invalid_rows_before_creating_dispatch(self):
        p = self.root / "bad.json"
        for rows in ([[0] * 214], [[True] * 215], [[2] * 215], [[0] * 215] * 21):
            with self.subTest(rows=repr(rows)[:30]):
                p.write_text(json.dumps({"feature_rows": rows}))
                with self.assertRaises(ValueError):
                    create_batches(p, self.root / "not-created")


if __name__ == "__main__":
    unittest.main()
