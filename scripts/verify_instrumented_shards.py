#!/usr/bin/env python3
"""Fail closed unless every API/shard executes the complete instrumented test inventory."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

EXPECTED_APIS = {26, 28, 33, 34, 36}
EXPECTED_SHARDS = 2
EXPECTED_TESTS_PER_API = int(os.environ.get("EXPECTED_TESTS_PER_API", "85"))


def fail(message: str) -> None:
    print("Instrumented shard verification FAILED: " + message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("Usage: verify_instrumented_shards.py <downloaded-artifact-root>")

    matrix_result = os.environ.get("MATRIX_RESULT", "")
    if matrix_result != "success":
        fail(f"API/shard matrix job result was {matrix_result or 'unset'}, not success.")

    root = Path(sys.argv[1])
    if not root.is_dir():
        fail(f"Downloaded emulator artifact directory is missing: {root}")

    result_files = sorted(root.rglob("instrumentation-result.json"))
    expected_pairs = {
        (api, shard)
        for api in EXPECTED_APIS
        for shard in range(EXPECTED_SHARDS)
    }
    if len(result_files) != len(expected_pairs):
        fail(
            f"Expected exactly {len(expected_pairs)} shard result files; "
            f"found {len(result_files)}."
        )

    results: dict[tuple[int, int], dict] = {}
    tests_by_api: dict[int, set[str]] = {api: set() for api in EXPECTED_APIS}
    total_by_api: dict[int, int] = {api: 0 for api in EXPECTED_APIS}

    for result_file in result_files:
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            fail(f"Cannot read {result_file}: {error}")

        try:
            api = int(data["api_level"])
            shard = int(data["shard_index"])
            shard_count = int(data["num_shards"])
            executed = int(data["executed_tests"])
            reported = int(data["reported_test_cases"])
            exit_code = int(data["exit_code"])
            cases = data["test_cases"]
            status = data["result"]
            log_name = data["instrumentation_log"]
        except (KeyError, TypeError, ValueError) as error:
            fail(f"Malformed shard result {result_file}: {error}")

        pair = (api, shard)
        if pair not in expected_pairs:
            fail(f"Unexpected API/shard result: API {api}, shard {shard}.")
        if pair in results:
            fail(f"Duplicate result for API {api}, shard {shard}.")
        if shard_count != EXPECTED_SHARDS:
            fail(f"API {api}, shard {shard} reported num_shards={shard_count}.")
        if status != "passed" or exit_code != 0:
            fail(f"API {api}, shard {shard} did not pass (status={status}, exit={exit_code}).")
        if not isinstance(cases, list) or any(not isinstance(case, str) or not case for case in cases):
            fail(f"API {api}, shard {shard} has an invalid test-case inventory.")
        if executed <= 0 or reported != executed or len(cases) != executed:
            fail(
                f"API {api}, shard {shard} has inconsistent counts: "
                f"summary={executed}, reported={reported}, inventory={len(cases)}."
            )
        if len(set(cases)) != len(cases):
            fail(f"API {api}, shard {shard} reports duplicate test cases.")
        log_path = result_file.parent / str(log_name)
        if not log_path.is_file() or log_path.stat().st_size == 0:
            fail(f"API {api}, shard {shard} is missing its instrumentation log.")

        collisions = tests_by_api[api].intersection(cases)
        if collisions:
            example = sorted(collisions)[0]
            fail(f"API {api} ran test {example} in more than one shard.")
        tests_by_api[api].update(cases)
        total_by_api[api] += executed
        results[pair] = data

    missing = sorted(expected_pairs - results.keys())
    if missing:
        fail("Missing API/shard results: " + ", ".join(f"{api}/{shard}" for api, shard in missing))

    for api in sorted(EXPECTED_APIS):
        union_count = len(tests_by_api[api])
        total_count = total_by_api[api]
        if total_count != EXPECTED_TESTS_PER_API or union_count != EXPECTED_TESTS_PER_API:
            fail(
                f"API {api} did not cover the full {EXPECTED_TESTS_PER_API}-test inventory: "
                f"shard total={total_count}, unique tests={union_count}."
            )
        per_shard = [
            results[(api, shard)]["executed_tests"]
            for shard in range(EXPECTED_SHARDS)
        ]
        if any(count <= 0 for count in per_shard):
            fail(f"API {api} contains an empty shard: {per_shard}.")

        print(
            f"API {api}: shards 0/{EXPECTED_SHARDS} and 1/{EXPECTED_SHARDS} passed; "
            f"tests per shard={per_shard}; {union_count} unique tests covered."
        )

    print(
        f"Instrumented shard verification passed: {len(expected_pairs)} shards, "
        f"{len(EXPECTED_APIS)} API levels, {EXPECTED_TESTS_PER_API} unique tests per API."
    )


if __name__ == "__main__":
    main()
