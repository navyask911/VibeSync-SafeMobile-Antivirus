#!/usr/bin/env python3
"""Create exact GitHub repository_dispatch envelopes, max 10 feature rows each.

Reads only derived 215-bit vectors; never uploads APKs, hashes, labels or secrets.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path

MAX_FILE_BYTES = 256 * 1024
FEATURES = 215
BATCH_SIZE = 10
MAX_ROWS = 20


def create_batches(source: Path, destination: Path) -> list[Path]:
    if not source.is_file() or source.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Missing or oversized compact feature payload")
    input_data = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(input_data, dict) or set(input_data) != {"feature_rows"}:
        raise ValueError("Only feature_rows is allowed in the dispatch source")
    rows = input_data["feature_rows"]
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
        payload = {
            "event_type": "new_malware_features",
            "client_payload": {"feature_rows": rows[offset:offset + BATCH_SIZE]},
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
