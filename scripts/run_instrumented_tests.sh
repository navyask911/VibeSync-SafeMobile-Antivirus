#!/usr/bin/env bash
# Validate the AVD before installing and running one AndroidJUnitRunner shard.
set -uo pipefail

cleanup_crashpad() {
  (
    sleep 30
    for attempt in 1 2 3 4 5 6; do
      if ! pgrep -f '[/]crashpad_handler([[:space:]]|$)' >/dev/null 2>&1; then break; fi
      pkill -9 -f '[/]crashpad_handler([[:space:]]|$)' || true
      sleep 5
    done
  ) || true
}

DEVICE_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
EXPECTED_API="${EXPECTED_API_LEVEL:-}"
NUM_SHARDS="${INSTRUMENTATION_NUM_SHARDS:-1}"
SHARD_INDEX="${INSTRUMENTATION_SHARD_INDEX:-0}"
DIAGNOSTICS_DIR="build/emulator-diagnostics"
INSTRUMENTATION_LOG="$DIAGNOSTICS_DIR/instrumentation-api${EXPECTED_API}-shard${SHARD_INDEX}.log"
RESULT_FILE="$DIAGNOSTICS_DIR/instrumentation-result.json"
executed_tests=0
mkdir -p "$DIAGNOSTICS_DIR"

if [[ ! "$EXPECTED_API" =~ ^[0-9]+$ ||
      ! "$NUM_SHARDS" =~ ^[1-9][0-9]*$ ||
      ! "$SHARD_INDEX" =~ ^[0-9]+$ ]] ||
   (( SHARD_INDEX >= NUM_SHARDS )); then
  echo "Invalid emulator API or AndroidJUnitRunner shard configuration." >&2
  exit 2
fi

write_shard_result() {
  local exit_code="$1"
  python3 - "$RESULT_FILE" "$EXPECTED_API" "$SHARD_INDEX" "$NUM_SHARDS" \
    "$exit_code" "$executed_tests" "$INSTRUMENTATION_LOG" <<'PY'
import json
import pathlib
import re
import sys

result_path, api, shard, shard_count, exit_code, summary_count, log_path = sys.argv[1:]
summary_count = int(summary_count)
cases = []
current = {}
log = pathlib.Path(log_path)
if log.is_file():
    for raw_line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        match = re.search(r"INSTRUMENTATION_STATUS: (class|test)=(.*)$", line)
        if match:
            current[match.group(1)] = match.group(2).strip()
            continue
        match = re.search(r"INSTRUMENTATION_STATUS_CODE: (-?[0-9]+)$", line)
        if match:
            if match.group(1) in {"0", "-2", "-3", "-4", "-5"}:
                if current.get("class") and current.get("test"):
                    cases.append(current["class"] + "#" + current["test"])
            current = {}

unique_cases = len(set(cases)) == len(cases)
passed = int(exit_code) == 0 and summary_count > 0 and len(cases) == summary_count and unique_cases
payload = {
    "api_level": int(api) if api.isdigit() else api,
    "shard_index": int(shard),
    "num_shards": int(shard_count),
    "executed_tests": summary_count,
    "reported_test_cases": len(cases),
    "test_cases": cases,
    "result": "passed" if passed else "failed",
    "exit_code": int(exit_code),
    "instrumentation_log": log.name,
}
pathlib.Path(result_path).parent.mkdir(parents=True, exist_ok=True)
temporary = pathlib.Path(result_path + ".tmp")
temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
temporary.replace(result_path)
print(f"Shard summary: API {api}, shard {shard}/{shard_count}, {summary_count} tests, {payload['result']}.")
PY
}
trap 'exit_code=$?; write_shard_result "$exit_code"; cleanup_crashpad' EXIT

capture_diagnostics() {
  local suffix="${1:-}"
  timeout 20s adb -s "$DEVICE_SERIAL" logcat -b all -d -t 30000 \
    > "$DIAGNOSTICS_DIR/logcat${suffix}.txt" 2>&1 || true
  timeout 15s adb -s "$DEVICE_SERIAL" shell getprop \
    > "$DIAGNOSTICS_DIR/getprop${suffix}.txt" 2>&1 || true
  timeout 15s adb -s "$DEVICE_SERIAL" shell service check package \
    > "$DIAGNOSTICS_DIR/package-service${suffix}.txt" 2>&1 || true
  timeout 15s adb -s "$DEVICE_SERIAL" shell dumpsys package com.vibesync.antivirus.debug \
    > "$DIAGNOSTICS_DIR/target-package${suffix}.txt" 2>&1 || true
  timeout 15s adb -s "$DEVICE_SERIAL" shell dumpsys package com.vibesync.antivirus.debug.test \
    > "$DIAGNOSTICS_DIR/test-package${suffix}.txt" 2>&1 || true
}

runtime_ready() {
  local state boot sdk package_service packages
  state="$(timeout 10s adb -s "$DEVICE_SERIAL" get-state 2>/dev/null | tr -d '\r' || true)"
  [[ "$state" == "device" ]] || return 1

  boot="$(timeout 10s adb -s "$DEVICE_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r[:space:]' || true)"
  [[ "$boot" == "1" ]] || return 1

  sdk="$(timeout 10s adb -s "$DEVICE_SERIAL" shell getprop ro.build.version.sdk 2>/dev/null | tr -d '\r[:space:]' || true)"
  [[ "$sdk" =~ ^[0-9]+$ ]] || return 1
  if [[ -n "$EXPECTED_API" && "$sdk" != "$EXPECTED_API" ]]; then
    echo "Expected Android API $EXPECTED_API but connected emulator reports API $sdk." >&2
    return 1
  fi

  package_service="$(timeout 10s adb -s "$DEVICE_SERIAL" shell service check package 2>&1 || true)"
  [[ "$package_service" == *"found"* ]] || return 1

  packages="$(timeout 15s adb -s "$DEVICE_SERIAL" shell pm list packages 2>&1 || true)"
  [[ "$packages" == *"package:"* && "$packages" != *"Can't find service: package"* ]] || return 1
  return 0
}

wait_for_runtime() {
  local timeout_seconds="$1"
  local description="$2"
  local deadline=$((SECONDS + timeout_seconds))
  local last_report=0
  echo "Waiting up to ${timeout_seconds}s for $description (device=$DEVICE_SERIAL, expected API=${EXPECTED_API:-not set})."
  until (( SECONDS >= deadline )); do
    if runtime_ready; then
      echo "Android framework and PackageManager are responsive."
      return 0
    fi
    if (( SECONDS - last_report >= 15 )); then
      echo "Android framework is not ready yet; continuing bounded health checks."
      last_report=$SECONDS
    fi
    sleep 5
  done
  return 1
}

if ! timeout 15s adb start-server; then
  echo "ADB server did not start within 15 seconds." >&2
  exit 2
fi
if ! wait_for_runtime 180 "initial emulator startup"; then
  echo "Emulator booted at the ADB level but Android framework services did not become ready; capturing pre-reboot diagnostics."
  capture_diagnostics "-pre-reboot"

  # A single clean reboot can recover a booted AVD whose system_server/PackageManager is wedged.
  timeout 15s adb -s "$DEVICE_SERIAL" reboot || true
  if ! wait_for_runtime 300 "emulator recovery after one reboot"; then
    echo "Emulator did not recover. Capturing diagnostics and failing before Gradle/device installation."
    capture_diagnostics "-failed-preflight"
    exit 2
  fi
fi

# APKs are prebuilt by CI before emulator startup, so Gradle only needs to install and run them.
# The 200-real-APK benchmark uses a separately staged batch.json and runs
# IndustryBenchmarkInstrumentedTest explicitly in industry-benchmark.yml.
# Normal emulator CI excludes only that corpus-dependent test; remaining tests
# are partitioned by AndroidJUnitRunner's numShards/shardIndex support.
benchmark_class="com.vibesync.antivirus.core.engine.IndustryBenchmarkInstrumentedTest"
instrument_fixture_args=(-e notClass "$benchmark_class")
if [[ -f build/siren-test/SafeMobile-Siren-Test.apk ]]; then
  if ! timeout 60s adb -s "$DEVICE_SERIAL" push build/siren-test/SafeMobile-Siren-Test.apk /data/local/tmp/SafeMobile-Siren-Test.apk; then
    echo "Could not stage the harmless siren fixture within 60 seconds." >&2
    capture_diagnostics "-fixture-push-failed"
    exit 3
  fi
  instrument_fixture_args+=(-e sirenFixturePath /data/local/tmp/SafeMobile-Siren-Test.apk)
else
  echo "Required prebuilt harmless siren fixture is missing." >&2
  exit 1
fi
app_apk="app/build/outputs/apk/offline/debug/app-offline-debug.apk"
test_apk="app/build/outputs/apk/androidTest/offline/debug/app-offline-debug-androidTest.apk"


test_apk="app/build/outputs/apk/androidTest/offline/debug/app-offline-debug-androidTest.apk"

run_prebuilt_instrumentation() {
  local api="$1"
  local instrument_status=0

  if [[ ! -s "$app_apk" || ! -s "$test_apk" ]]; then
    echo "Prebuilt app or instrumentation APK is missing; refusing to report instrumentation success." >&2
    return 2
  fi

  echo "Installing prebuilt offline debug APK for API $api."
  timeout 180s adb -s "$DEVICE_SERIAL" install -r -t "$app_apk" || return $?
  timeout 180s adb -s "$DEVICE_SERIAL" install -r -t "$test_apk" || return $?

  echo "Running AndroidJUnitRunner shard $SHARD_INDEX/$NUM_SHARDS on API $api."
  timeout 900s adb -s "$DEVICE_SERIAL" shell am instrument -w -r \
    -e numShards "$NUM_SHARDS" \
    -e shardIndex "$SHARD_INDEX" \
    "${instrument_fixture_args[@]}" \
    com.vibesync.antivirus.debug.test/androidx.test.runner.AndroidJUnitRunner \
    2>&1 | tee "$INSTRUMENTATION_LOG"
  instrument_status=${PIPESTATUS[0]}

  if [[ "$INSTRUMENTATION_LOG" =~ OK[[:space:]]\(([0-9]+)[[:space:]]tests?\) ]]; then
    executed_tests="${BASH_REMATCH[1]}"
  else
    executed_tests=0
  fi

  if [[ "$instrument_status" -eq 0 && "$executed_tests" -gt 0 ]] &&
     grep -Eq 'INSTRUMENTATION_CODE: -1' "$INSTRUMENTATION_LOG" &&
     ! grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|INSTRUMENTATION_ABORTED|Process crashed|FAILURE:' "$INSTRUMENTATION_LOG"; then
    echo "API $api shard $SHARD_INDEX/$NUM_SHARDS executed $executed_tests tests."
    return 0
  fi

  echo "API $api shard $SHARD_INDEX/$NUM_SHARDS did not report a verified passing test suite." >&2
  return 1
}

test_status=0
run_prebuilt_instrumentation "$EXPECTED_API" || test_status=$?

capture_diagnostics
timeout 15s adb -s "$DEVICE_SERIAL" shell run-as com.vibesync.antivirus.debug \
  cat files/quarantine-roundtrip-diagnostics.txt \
  > "$DIAGNOSTICS_DIR/quarantine-roundtrip.txt" 2>&1 || true
timeout 15s adb -s "$DEVICE_SERIAL" shell run-as com.vibesync.antivirus.debug \
  cat files/safemobile_private_text_diagnostics.txt \
  > "$DIAGNOSTICS_DIR/private-text.txt" 2>&1 || true

exit "$test_status"
