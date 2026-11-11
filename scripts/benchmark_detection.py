#!/usr/bin/env python3
"""Evaluate an externally generated, provenance-bound SafeMobile APK benchmark report.

This script never runs the Android scanner and never invents corpus results. With no input
it emits NOT_MEASURED. Device runs must supply actual scan verdicts, elapsed times, and
optional memory deltas plus the exact dataset/corpus/device/commit provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
VERDICTS = {"THREAT", "SUSPICIOUS", "NO_MATCH", "NOT_SCANNED"}
LABELS = {"malicious", "benign"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$", re.IGNORECASE)
REQUIRED_DATASET_FIELDS = (
    "name", "revision", "license", "source", "manifest_sha256",
    "corpus_sha256", "reference_device", "platform_version", "commit_sha",
)


class BenchmarkInputError(ValueError):
    pass


def _positive_number(value: Any, field: str, *, allow_zero: bool = True) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise BenchmarkInputError(f"{field} must be a finite number")
    result = float(value)
    if result < 0 or (not allow_zero and result == 0):
        raise BenchmarkInputError(f"{field} must be {'positive' if not allow_zero else 'non-negative'}")
    return result


def validate_report(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise BenchmarkInputError("top-level JSON value must be an object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise BenchmarkInputError(f"schema_version must be {SCHEMA_VERSION}")
    dataset = data.get("dataset")
    if not isinstance(dataset, dict):
        raise BenchmarkInputError("dataset metadata object is required")
    for field in REQUIRED_DATASET_FIELDS:
        if not isinstance(dataset.get(field), str) or not dataset[field].strip():
            raise BenchmarkInputError(f"dataset.{field} is required")
    if not SHA256_RE.fullmatch(dataset["manifest_sha256"]):
        raise BenchmarkInputError("dataset.manifest_sha256 must be a SHA-256 hex digest")
    if not SHA256_RE.fullmatch(dataset["corpus_sha256"]):
        raise BenchmarkInputError("dataset.corpus_sha256 must be a SHA-256 hex digest")
    if not COMMIT_RE.fullmatch(dataset["commit_sha"]):
        raise BenchmarkInputError("dataset.commit_sha must be a 40-64 character Git SHA")
    samples = data.get("samples")
    if not isinstance(samples, list) or not samples:
        raise BenchmarkInputError("samples must be a non-empty array of completed scan outcomes")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            raise BenchmarkInputError(f"samples[{index}] must be an object")
        sample_id = sample.get("sample_id")
        label = sample.get("label")
        verdict = sample.get("verdict")
        if not isinstance(sample_id, str) or not sample_id.strip() or len(sample_id) > 120:
            raise BenchmarkInputError(f"samples[{index}].sample_id must be a short non-empty anonymized ID")
        if sample_id in seen:
            raise BenchmarkInputError(f"duplicate sample_id: {sample_id}")
        seen.add(sample_id)
        if not isinstance(label, str) or label not in LABELS:
            raise BenchmarkInputError(f"samples[{index}].label must be malicious or benign")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            raise BenchmarkInputError(f"samples[{index}].verdict must be one of {sorted(VERDICTS)}")
        if "duration_ms" not in sample:
            raise BenchmarkInputError(f"samples[{index}].duration_ms is required")
        duration = _positive_number(sample["duration_ms"], f"samples[{index}].duration_ms")
        memory = sample.get("peak_memory_delta_kb")
        if memory is not None:
            memory = _positive_number(memory, f"samples[{index}].peak_memory_delta_kb")
        normalized.append({
            "sample_id": sample_id, "label": label, "verdict": verdict,
            "duration_ms": duration, "peak_memory_delta_kb": memory,
        })
    data = dict(data)
    data["dataset"] = dict(dataset)
    data["samples"] = normalized
    return data


def _percentile_nearest_rank(values: list[float], percentile: float) -> float:
    if not values:
        raise ValueError("percentile requires values")
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def _not_measured_metrics() -> dict[str, Any]:
    return {
        "malware_tpr": "NOT MEASURED",
        "benign_fpr": "NOT MEASURED",
        "triage_tpr": "NOT MEASURED",
        "triage_fpr": "NOT MEASURED",
        "confirmed_precision": "NOT MEASURED",
        "triage_precision": "NOT MEASURED",
        "not_scanned_rate": "NOT MEASURED",
        "mean_latency_ms": "NOT MEASURED",
        "p50_latency_ms": "NOT MEASURED",
        "p95_latency_ms": "NOT MEASURED",
        "p95_memory_delta_kb": "NOT MEASURED",
    }



def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_provenance(
    data: Any, dataset_manifest_path: Path | None, corpus_manifest_path: Path | None, sample_root: Path | None,
    approved_manifest_sha256: str | None = None,
) -> tuple[bool, list[str]]:
    if approved_manifest_sha256 is None or not SHA256_RE.fullmatch(approved_manifest_sha256):
        return False, ["No owner-approved dataset manifest SHA-256 allowlist was supplied; metrics remain NOT MEASURED."]
    if dataset_manifest_path is None or corpus_manifest_path is None or sample_root is None:
        return False, ["Provide --dataset-manifest, --corpus-manifest and --sample-root to verify provenance before metrics can be MEASURED."]
    report = validate_report(data)
    dataset = report["dataset"]
    actual_manifest_sha256 = _sha256_file(dataset_manifest_path)
    if actual_manifest_sha256 != dataset["manifest_sha256"].lower():
        raise BenchmarkInputError("dataset manifest SHA-256 does not match dataset.manifest_sha256")
    if actual_manifest_sha256 != approved_manifest_sha256.lower():
        return False, ["Dataset manifest digest is not on the owner-approved allowlist; metrics remain NOT MEASURED."]
    try:
        metadata = json.loads(dataset_manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BenchmarkInputError("dataset manifest must be JSON with name, revision, license and source metadata") from error
    if not isinstance(metadata, dict) or metadata.get("schema_version") != 1:
        raise BenchmarkInputError("dataset manifest must use schema_version 1")
    for field in ("name", "revision", "license", "source"):
        if metadata.get(field) != dataset.get(field):
            raise BenchmarkInputError(f"dataset metadata does not match the provenance manifest field {field}")
    if _sha256_file(corpus_manifest_path) != dataset["corpus_sha256"].lower():
        raise BenchmarkInputError("corpus manifest SHA-256 does not match dataset.corpus_sha256")
    try:
        corpus = json.loads(corpus_manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise BenchmarkInputError("corpus manifest must be valid JSON") from error
    if not isinstance(corpus, dict) or corpus.get("schema_version") != 1 or not isinstance(corpus.get("samples"), list):
        raise BenchmarkInputError("corpus manifest must contain schema_version 1 and a samples array")
    root = sample_root.resolve()
    expected: dict[str, tuple[str, str]] = {}
    for index, item in enumerate(corpus["samples"]):
        if not isinstance(item, dict):
            raise BenchmarkInputError(f"corpus.samples[{index}] must be an object")
        sample_id, label, relative_path, expected_hash = (item.get("sample_id"), item.get("label"), item.get("relative_path"), item.get("sha256"))
        if not isinstance(sample_id, str) or not sample_id.strip() or sample_id in expected:
            raise BenchmarkInputError(f"corpus.samples[{index}] has an empty or duplicate sample_id")
        if not isinstance(label, str) or label not in LABELS:
            raise BenchmarkInputError(f"corpus.samples[{index}].label must be malicious or benign")
        if not isinstance(relative_path, str) or not relative_path or relative_path.startswith(("/", chr(92))) or chr(92) in relative_path or any(part in {"", ".", ".."} for part in relative_path.split("/")):
            raise BenchmarkInputError(f"corpus.samples[{index}].relative_path must be a safe relative POSIX path")
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            raise BenchmarkInputError(f"corpus.samples[{index}].sha256 must be a SHA-256 hex digest")
        path = (root / relative_path).resolve()
        try:
            path.relative_to(root)
        except ValueError as error:
            raise BenchmarkInputError(f"corpus sample path escapes sample root: {sample_id}") from error
        if not path.is_file():
            raise BenchmarkInputError(f"corpus sample file is missing: {sample_id}")
        if _sha256_file(path) != expected_hash.lower():
            raise BenchmarkInputError(f"APK SHA-256 mismatch for corpus sample: {sample_id}")
        expected[sample_id] = (label, expected_hash.lower())
    actual = {sample["sample_id"]: sample["label"] for sample in report["samples"]}
    if set(actual) != set(expected):
        raise BenchmarkInputError("benchmark result sample IDs do not exactly match the verified corpus manifest")
    for sample_id, label in actual.items():
        if expected[sample_id][0] != label:
            raise BenchmarkInputError(f"benchmark label mismatch for sample {sample_id}")
    return True, []


def evaluate_report(data: Any, minimum_benign_samples: int = 1000, provenance_verified: bool = False, provenance_reasons: list[str] | None = None) -> dict[str, Any]:
    if minimum_benign_samples < 1:
        raise ValueError("minimum_benign_samples must be at least 1")
    report = validate_report(data)
    samples = report["samples"]
    malicious = [s for s in samples if s["label"] == "malicious"]
    benign = [s for s in samples if s["label"] == "benign"]
    unscreened = sum(s["verdict"] == "NOT_SCANNED" for s in samples)
    readiness_reasons: list[str] = []
    if not provenance_verified:
        readiness_reasons.extend(provenance_reasons or ["Dataset manifest, corpus manifest, and APK SHA-256 values have not been verified."])
    if not malicious:
        readiness_reasons.append("No labeled malicious APK samples are present.")
    if len(benign) < minimum_benign_samples:
        readiness_reasons.append(f"Only {len(benign)} benign samples are present; at least {minimum_benign_samples} are required.")
    if any(s["peak_memory_delta_kb"] is None for s in samples):
        memory_ready = False
    else:
        memory_ready = True
    measured = not readiness_reasons
    metrics: dict[str, Any] = _not_measured_metrics()
    if measured:
        confirmed_malicious = sum(s["verdict"] == "THREAT" for s in malicious)
        confirmed_benign = sum(s["verdict"] == "THREAT" for s in benign)
        triage_malicious = sum(s["verdict"] in {"THREAT", "SUSPICIOUS"} for s in malicious)
        triage_benign = sum(s["verdict"] in {"THREAT", "SUSPICIOUS"} for s in benign)
        all_threats = sum(s["verdict"] == "THREAT" for s in samples)
        all_flagged = sum(s["verdict"] in {"THREAT", "SUSPICIOUS"} for s in samples)
        durations = [s["duration_ms"] for s in samples]
        metrics = {
            "malware_tpr": confirmed_malicious / len(malicious),
            "benign_fpr": confirmed_benign / len(benign),
            "triage_tpr": triage_malicious / len(malicious),
            "triage_fpr": triage_benign / len(benign),
            "confirmed_precision": confirmed_malicious / all_threats if all_threats else 0.0,
            "triage_precision": triage_malicious / all_flagged if all_flagged else 0.0,
            "not_scanned_rate": unscreened / len(samples),
            "mean_latency_ms": statistics.fmean(durations),
            "p50_latency_ms": statistics.median(durations),
            "p95_latency_ms": _percentile_nearest_rank(durations, 0.95),
            "p95_memory_delta_kb": _percentile_nearest_rank([s["peak_memory_delta_kb"] for s in samples], 0.95) if memory_ready else "NOT MEASURED",
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "MEASURED" if measured else "NOT_MEASURED",
        "dataset": report["dataset"],
        "sample_counts": {"total": len(samples), "malicious": len(malicious), "benign": len(benign), "not_scanned": unscreened},
        "minimum_benign_samples": minimum_benign_samples,
        "provenance_verification": "VERIFIED" if provenance_verified else "NOT_VERIFIED",
        "readiness_reasons": readiness_reasons,
        "metrics": metrics,
        "regression_gate": {"status": "NOT_RUN", "reasons": ["No comparable measured baseline was supplied."]},
        "notes": [
            "THREAT counts as a confirmed match. SUSPICIOUS is reported separately as triage, not as confirmed malware.",
            "NOT_SCANNED is counted as a missed malicious sample for TPR and is always reported separately.",
            "This report reflects an external device-run result file; this script does not execute the Android scanner.",
            "A measured value describes only the exact dataset revision, corpus digest, app commit, OS and reference device listed above.",
        ],
    }


def apply_regression_gate(
    current: dict[str, Any],
    baseline: dict[str, Any],
    max_fpr_increase: float = 0.005,
    max_p95_latency_increase: float = 0.20,
) -> dict[str, Any]:
    if max_fpr_increase < 0 or max_p95_latency_increase < 0:
        raise ValueError("regression tolerances must be non-negative")
    reasons: list[str] = []
    if current.get("status") != "MEASURED" or baseline.get("status") != "MEASURED":
        reasons.append("Both current and baseline reports must be MEASURED.")
    else:
        current_ds = current.get("dataset", {})
        baseline_ds = baseline.get("dataset", {})
        for field in ("name", "revision", "manifest_sha256", "corpus_sha256", "reference_device", "platform_version"):
            if current_ds.get(field) != baseline_ds.get(field):
                reasons.append(f"Dataset/device provenance changed: {field}.")
        current_metrics = current.get("metrics", {})
        baseline_metrics = baseline.get("metrics", {})
        try:
            if float(current_metrics["benign_fpr"]) > float(baseline_metrics["benign_fpr"]) + max_fpr_increase:
                reasons.append("Benign false-positive rate exceeded the allowed absolute increase.")
            baseline_latency = float(baseline_metrics["p95_latency_ms"])
            current_latency = float(current_metrics["p95_latency_ms"])
            if baseline_latency > 0 and current_latency > baseline_latency * (1 + max_p95_latency_increase):
                reasons.append("P95 scan latency exceeded the allowed relative increase.")
        except (KeyError, TypeError, ValueError):
            reasons.append("Required measured baseline metrics are missing.")
    return {"status": "FAIL" if reasons else "PASS", "reasons": reasons,
            "thresholds": {"max_absolute_fpr_increase": max_fpr_increase, "max_relative_p95_latency_increase": max_p95_latency_increase}}


def not_measured_report(reason: str, minimum_benign_samples: int = 1000) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION, "status": "NOT_MEASURED",
        "dataset": None,
        "provenance_verification": "NOT_VERIFIED",
        "sample_counts": {"total": 0, "malicious": 0, "benign": 0, "not_scanned": 0},
        "minimum_benign_samples": minimum_benign_samples,
        "readiness_reasons": [reason],
        "metrics": _not_measured_metrics(),
        "regression_gate": {"status": "NOT_RUN", "reasons": ["No measured corpus result and baseline were supplied."]},
        "notes": ["The benchmark runner never estimates or fabricates metrics."],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, help="JSON report created by an on-device benchmark run")
    parser.add_argument("--output", type=Path, help="Write canonical JSON result to this path (default: stdout)")
    parser.add_argument("--baseline", type=Path, help="Prior MEASURED result JSON for comparable regression checks")
    parser.add_argument("--approved-dataset-manifest-sha256", default=os.environ.get("SAFE_MOBILE_APPROVED_DATASET_MANIFEST_SHA256"), help="Owner-approved SHA-256 allowlist value for dataset manifest; default: SAFE_MOBILE_APPROVED_DATASET_MANIFEST_SHA256 environment variable")
    parser.add_argument("--dataset-manifest", type=Path, help="Local JSON provenance manifest whose SHA-256 matches dataset.manifest_sha256")
    parser.add_argument("--corpus-manifest", type=Path, help="Local corpus JSON manifest whose SHA-256 matches dataset.corpus_sha256")
    parser.add_argument("--sample-root", type=Path, help="Root directory for every APK listed in the corpus manifest")
    parser.add_argument("--min-benign", type=int, default=1000, help="Minimum benign samples required for publishable metrics (default: 1000)")
    parser.add_argument("--max-fpr-increase", type=float, default=0.005, help="Maximum allowed absolute FPR increase over baseline")
    parser.add_argument("--max-p95-latency-increase", type=float, default=0.20, help="Maximum allowed relative P95 latency increase over baseline")
    parser.add_argument("--require-measured", action="store_true", help="Return exit code 3 if results are not MEASURED")
    args = parser.parse_args(argv)
    if args.min_benign < 1:
        parser.error("--min-benign must be at least 1")
    try:
        if args.input is None:
            result = not_measured_report("No on-device benchmark result file was supplied; no approved APK corpus is bundled in CI.", args.min_benign)
        else:
            with args.input.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            provenance_verified, provenance_reasons = verify_provenance(data, args.dataset_manifest, args.corpus_manifest, args.sample_root, args.approved_dataset_manifest_sha256)
            result = evaluate_report(data, args.min_benign, provenance_verified, provenance_reasons)
        if args.baseline is not None:
            with args.baseline.open("r", encoding="utf-8") as handle:
                baseline = json.load(handle)
            result["regression_gate"] = apply_regression_gate(
                result, baseline, args.max_fpr_increase, args.max_p95_latency_increase
            )
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            print(f"Benchmark status: {result['status']} — report written to {args.output}")
        else:
            sys.stdout.write(rendered)
        if result.get("regression_gate", {}).get("status") == "FAIL":
            return 4
        if args.require_measured and result["status"] != "MEASURED":
            return 3
        return 0
    except (OSError, json.JSONDecodeError, BenchmarkInputError) as error:
        print(f"benchmark input error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())