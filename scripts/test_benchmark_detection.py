import copy
import unittest

from benchmark_detection import apply_regression_gate, evaluate_report, not_measured_report


def sample_report(benign_count=3):
    samples = [
        {"sample_id": "mal-1", "label": "malicious", "verdict": "THREAT", "duration_ms": 100, "peak_memory_delta_kb": 500},
        {"sample_id": "mal-2", "label": "malicious", "verdict": "SUSPICIOUS", "duration_ms": 130, "peak_memory_delta_kb": 600},
        {"sample_id": "mal-3", "label": "malicious", "verdict": "NOT_SCANNED", "duration_ms": 15, "peak_memory_delta_kb": 100},
    ]
    outcomes = ["NO_MATCH", "NO_MATCH", "THREAT", "SUSPICIOUS", "NOT_SCANNED"]
    for idx in range(benign_count):
        samples.append({"sample_id": f"ben-{idx}", "label": "benign", "verdict": outcomes[idx % len(outcomes)],
                        "duration_ms": 20 + idx, "peak_memory_delta_kb": 200 + idx})
    return {
        "schema_version": 1,
        "dataset": {
            "name": "test-fixture", "revision": "v1", "license": "TEST", "source": "unit test fixture",
            "manifest_sha256": "a" * 64, "corpus_sha256": "b" * 64, "reference_device": "fixture",
            "platform_version": "test", "commit_sha": "c" * 40
        },
        "samples": samples
    }


class BenchmarkDetectionTests(unittest.TestCase):
    def test_missing_input_never_fabricates_metrics(self):
        result = not_measured_report("no corpus")
        self.assertEqual("NOT_MEASURED", result["status"])
        self.assertEqual("NOT MEASURED", result["metrics"]["malware_tpr"])
        self.assertEqual("NOT MEASURED", result["metrics"]["benign_fpr"])

    def test_small_fixture_keeps_efficacy_metrics_unmeasured(self):
        result = evaluate_report(sample_report(benign_count=3), minimum_benign_samples=1000)
        self.assertEqual("NOT_MEASURED", result["status"])
        self.assertEqual("NOT MEASURED", result["metrics"]["malware_tpr"])
        self.assertEqual(3, result["sample_counts"]["benign"])

    def test_measured_fixture_computes_confirmed_and_triage_metrics_separately(self):
        result = evaluate_report(sample_report(benign_count=1000), minimum_benign_samples=1000, provenance_verified=True)
        self.assertEqual("MEASURED", result["status"])
        self.assertAlmostEqual(1 / 3, result["metrics"]["malware_tpr"])
        self.assertAlmostEqual(2 / 3, result["metrics"]["triage_tpr"])
        self.assertEqual(0.2, result["metrics"]["benign_fpr"])
        self.assertGreater(result["metrics"]["p95_latency_ms"], 0)
        self.assertAlmostEqual(result["sample_counts"]["not_scanned"] / result["sample_counts"]["total"], result["metrics"]["not_scanned_rate"])

    def test_unverified_corpus_keeps_metrics_unmeasured_even_with_enough_samples(self):
        result = evaluate_report(sample_report(benign_count=1000), minimum_benign_samples=1000)
        self.assertEqual("NOT_MEASURED", result["status"])
        self.assertEqual("NOT_VERIFIED", result["provenance_verification"])

    def test_missing_owner_approval_keeps_verified_files_unmeasured(self):
        from benchmark_detection import verify_provenance
        verified, reasons = verify_provenance({}, None, None, None)
        self.assertFalse(verified)
        self.assertTrue(any("owner-approved" in reason for reason in reasons))

    def test_manifest_must_match_owner_approved_digest(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path
        from benchmark_detection import verify_provenance

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data = sample_report(benign_count=1)
            sample = root / "sample.apk"
            sample.write_bytes(b"APK fixture")
            corpus = {"schema_version": 1, "samples": [
                {"sample_id": "mal-1", "label": "malicious", "relative_path": "sample.apk",
                 "sha256": hashlib.sha256(b"APK fixture").hexdigest()}
            ]}
            corpus_bytes = json.dumps(corpus, sort_keys=True).encode()
            corpus_path = root / "corpus.json"
            corpus_path.write_bytes(corpus_bytes)
            metadata = {"schema_version": 1, "name": "test-fixture", "revision": "v1",
                        "license": "TEST", "source": "unit test fixture"}
            metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
            metadata_path = root / "dataset.json"
            metadata_path.write_bytes(metadata_bytes)
            data["samples"] = [sample for sample in data["samples"] if sample["sample_id"] == "mal-1"]
            data["dataset"]["manifest_sha256"] = hashlib.sha256(metadata_bytes).hexdigest()
            data["dataset"]["corpus_sha256"] = hashlib.sha256(corpus_bytes).hexdigest()
            verified, reasons = verify_provenance(data, metadata_path, corpus_path, root,
                approved_manifest_sha256="f" * 64)
            self.assertFalse(verified)
            self.assertTrue(any("allowlist" in reason for reason in reasons))

    def test_provenance_verification_checks_manifests_and_apk_bytes(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path
        from benchmark_detection import verify_provenance

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data = sample_report(benign_count=3)
            corpus_samples = []
            for sample in data["samples"]:
                relative = f"samples/{sample['sample_id']}.apk"
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(("fixture:" + sample["sample_id"]).encode())
                corpus_samples.append({
                    "sample_id": sample["sample_id"], "label": sample["label"],
                    "relative_path": relative, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()
                })
            corpus_content = json.dumps({"schema_version": 1, "samples": corpus_samples}, sort_keys=True).encode()
            corpus_path = root / "corpus.json"
            corpus_path.write_bytes(corpus_content)
            metadata = {
                "schema_version": 1, "name": "test-fixture", "revision": "v1",
                "license": "TEST", "source": "unit test fixture"
            }
            metadata_content = json.dumps(metadata, sort_keys=True).encode()
            metadata_path = root / "dataset.json"
            metadata_path.write_bytes(metadata_content)
            data["dataset"]["manifest_sha256"] = hashlib.sha256(metadata_content).hexdigest()
            data["dataset"]["corpus_sha256"] = hashlib.sha256(corpus_content).hexdigest()
            verified, reasons = verify_provenance(data, metadata_path, corpus_path, root, approved_manifest_sha256=hashlib.sha256(metadata_content).hexdigest())
            self.assertTrue(verified, reasons)
            result = evaluate_report(data, minimum_benign_samples=3, provenance_verified=verified)
            self.assertEqual("MEASURED", result["status"])

    def test_provenance_verification_rejects_changed_apk_bytes(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path
        from benchmark_detection import verify_provenance

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data = sample_report(benign_count=3)
            corpus_samples = []
            for sample in data["samples"]:
                relative = f"samples/{sample['sample_id']}.apk"
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(("expected:" + sample["sample_id"]).encode())
                corpus_samples.append({
                    "sample_id": sample["sample_id"], "label": sample["label"],
                    "relative_path": relative, "sha256": hashlib.sha256(target.read_bytes()).hexdigest()
                })
            corpus_content = json.dumps({"schema_version": 1, "samples": corpus_samples}, sort_keys=True).encode()
            corpus_path = root / "corpus.json"
            corpus_path.write_bytes(corpus_content)
            metadata = {
                "schema_version": 1, "name": "test-fixture", "revision": "v1",
                "license": "TEST", "source": "unit test fixture"
            }
            metadata_content = json.dumps(metadata, sort_keys=True).encode()
            metadata_path = root / "dataset.json"
            metadata_path.write_bytes(metadata_content)
            data["dataset"]["manifest_sha256"] = hashlib.sha256(metadata_content).hexdigest()
            data["dataset"]["corpus_sha256"] = hashlib.sha256(corpus_content).hexdigest()
            target = root / corpus_samples[0]["relative_path"]
            target.write_bytes(b"tampered APK bytes")
            with self.assertRaisesRegex(ValueError, "APK SHA-256 mismatch"):
                verify_provenance(data, metadata_path, corpus_path, root, approved_manifest_sha256=hashlib.sha256(metadata_content).hexdigest())

    def test_duplicate_sample_ids_are_rejected(self):
        data = sample_report()
        data["samples"].append(copy.deepcopy(data["samples"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate sample_id"):
            evaluate_report(data, minimum_benign_samples=1)

    def test_invalid_dataset_digests_are_rejected(self):
        data = sample_report()
        data["dataset"]["corpus_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "corpus_sha256"):
            evaluate_report(data, minimum_benign_samples=1)

    def test_regression_gate_requires_same_corpus_and_checks_fpr_and_latency(self):
        baseline = evaluate_report(sample_report(1000), minimum_benign_samples=1000, provenance_verified=True)
        current_data = sample_report(1000)
        current_data["dataset"]["commit_sha"] = "d" * 40
        for sample in current_data["samples"]:
            sample["duration_ms"] *= 2
        current = evaluate_report(current_data, minimum_benign_samples=1000, provenance_verified=True)
        gate = apply_regression_gate(current, baseline)
        self.assertEqual("FAIL", gate["status"])
        self.assertTrue(any("P95 scan latency" in reason for reason in gate["reasons"]))
        changed_dataset = copy.deepcopy(current)
        changed_dataset["dataset"]["corpus_sha256"] = "e" * 64
        self.assertTrue(any("corpus_sha256" in reason for reason in apply_regression_gate(changed_dataset, baseline)["reasons"]))


if __name__ == "__main__":
    unittest.main()