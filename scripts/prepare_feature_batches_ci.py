#!/usr/bin/env python3
"""Create exact GitHub repository_dispatch envelopes, max 10 feature rows each.

Reads only derived 215-bit vectors; never uploads APKs, hashes, labels or secrets.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

MAX_FILE_BYTES = 256 * 1024
FEATURES = 215
FEATURE_METADATA_FIELDS = {"sha256", "vt_malicious_count", "ha_threat_score", "ha_verdict"}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BATCH_SIZE = 10
MAX_ROWS = 20


def create_batches(source: Path, destination: Path) -> list[Path]:
    if not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Missing or oversized compact feature payload")
    input_data = json.loads(source.read_text(encoding="utf-8"))
    if (not isinstance(input_data, dict)
            or not set(input_data).issubset({"feature_rows", "feature_metadata"})
            or "feature_rows" not in input_data):
        raise ValueError("Only feature_rows and optional feature_metadata are allowed in the dispatch source")
    rows = input_data["feature_rows"]
    metadata = input_data.get("feature_metadata")
    if metadata is not None:
        if not isinstance(metadata, list) or len(metadata) != len(rows):
            raise ValueError("feature_metadata must align one-to-one with feature_rows")
        for index, record in enumerate(metadata):
            if not isinstance(record, dict) or set(record) != FEATURE_METADATA_FIELDS:
                raise ValueError(f"Invalid reputation metadata fields at index {index}")
            if not isinstance(record.get("sha256"), str) or not SHA256_RE.fullmatch(record["sha256"]):
                raise ValueError(f"Invalid reputation SHA-256 at index {index}")
            if type(record.get("vt_malicious_count")) is not int or record["vt_malicious_count"] < -1:
                raise ValueError(f"Invalid VirusTotal count at index {index}")
            score = record.get("ha_threat_score")
            if type(score) in (int, float):
                if not 0 <= score <= 100:
                    raise ValueError(f"Invalid Hybrid Analysis score at index {index}")
            elif score != "Not Found":
                raise ValueError(f"Invalid Hybrid Analysis score at index {index}")
            if not isinstance(record.get("ha_verdict"), str) or not record["ha_verdict"].strip():
                raise ValueError(f"Invalid Hybrid Analysis verdict at index {index}")
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Only 0..20 rows may be sent per six-hour run")
    for index, row in enumerate(rows):
        if (not isinstance(row, list) or len(row) != FEATURES
                or any(type(bit) is not int or bit not in (0, 1) for bit in row)):
            raise ValueError(f"Invalid binary feature row at index {index}")
    destination.mkdir(parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError("Batch directory must start empty")
    outputs = []
    for offset in range(0, len(rows), BATCH_SIZE):
        client_payload = {"feature_rows": rows[offset:offset + BATCH_SIZE]}
        if metadata is not None:
            client_payload["feature_metadata"] = metadata[offset:offset + BATCH_SIZE]
        payload = {
            "event_type": "new_malware_features",
            "client_payload": client_payload,
        }
        path = destination / f"batch-{len(outputs):02d}.json"
        path.write_text(json.dumps(payload, separators=(",", ":"), allow_nan=False) + "\n",
                        encoding="utf-8")
        outputs.append(path)
    print(f"Prepared {len(outputs)} GitHub dispatch batches, total {len(rows)} research vectors.")
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    create_batches(args.input, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
