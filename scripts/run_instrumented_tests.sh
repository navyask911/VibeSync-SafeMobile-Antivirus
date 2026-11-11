#!/usr/bin/env bash
# Wait for the Android framework (especially PackageManager) to become responsive before
# invoking Gradle. sys.boot_completed alone is not sufficient on slow/headless API 30+ AVDs.
set -uo pipefail

# reactivecircus/android-emulator-runner invokes 'script' via /usr/bin/sh -c.
# Its script input must be ONE shell command; keep this Bash EXIT trap here
# rather than passing a multiline YAML script that the action truncates.
cleanup_crashpad() {
  (
    sleep 30
    # Linux comm names truncate at 15 bytes, so pgrep -x crashpad_handler
    # can miss the process. Match the full executable path instead.
    for attempt in 1 2 3 4 5 6; do
      if ! pgrep -f '[/]crashpad_handler([[:space:]]|$)' >/dev/null 2>&1; then
        break
      fi
      pkill -9 -f '[/]crashpad_handler([[:space:]]|$)' || true
      sleep 5
    done
  ) || true
}
trap cleanup_crashpad EXIT

DEVICE_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
EXPECTED_API="${EXPECTED_API_LEVEL:-}"
DIAGNOSTICS_DIR="build/emulator-diagnostics"
mkdir -p "$DIAGNOSTICS_DIR"

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

adb start-server || true
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
# API 36's software-emulated system_server can stall if it competes with a 2 GiB Gradle JVM.
workers=2
heap=2g
if [[ "$EXPECTED_API" == "36" ]]; then
  workers=1
  heap=1024m
fi

# The 200-real-APK benchmark uses a separately staged batch.json and runs
# IndustryBenchmarkInstrumentedTest explicitly in industry-benchmark.yml.
# Normal emulator CI must run every other instrumentation test, but must not
# invoke the corpus-only benchmark without its verified input set.
# Never skip or ignore a failing ordinary test or synthesize benchmark data.
benchmark_class="com.vibesync.antivirus.core.engine.IndustryBenchmarkInstrumentedTest"
fixture_args=("-Pandroid.testInstrumentationRunnerArguments.notClass=$benchmark_class")
instrument_fixture_args=(-e notClass "$benchmark_class")
if [[ -f build/siren-test/SafeMobile-Siren-Test.apk ]]; then
  adb push build/siren-test/SafeMobile-Siren-Test.apk /data/local/tmp/SafeMobile-Siren-Test.apk
  fixture_args+=("-Pandroid.testInstrumentationRunnerArguments.sirenFixturePath=/data/local/tmp/SafeMobile-Siren-Test.apk")
  instrument_fixture_args+=(-e sirenFixturePath /data/local/tmp/SafeMobile-Siren-Test.apk)
elif [[ "${GITHUB_ACTIONS:-false}" == "true" ]]; then
  echo "Required background-install test fixture is missing." >&2
  exit 1
fi
gradle_log="$DIAGNOSTICS_DIR/connected-gradle.log"
./gradlew --no-daemon --max-workers="$workers" --no-parallel \
  -Dorg.gradle.jvmargs="-Xmx$heap -XX:ActiveProcessorCount=2 -Dfile.encoding=UTF-8" \
  "${fixture_args[@]}" connectedOfflineDebugAndroidTest 2>&1 | tee "$gradle_log"
test_status=${PIPESTATUS[0]}

# A lost API-level property in ddmlib means no tests actually executed. Recover *only* that
# infrastructure failure; never retry/override a real failing test assertion or lint gate.
if [[ "$EXPECTED_API" == "36" && "$test_status" -ne 0 ]] &&
   grep -Eq 'Unknown API Level|No compatible devices connected' "$gradle_log"; then
  echo "API 36 emulator property-query failure detected. Trying the prebuilt instrumentation APKs directly via ADB."
  timeout 15s adb kill-server || true
  timeout 15s adb start-server || true
  if ! wait_for_runtime 300 "API 36 ADB recovery"; then
    echo "ADB recovery failed; keeping instrumented test failure."
    capture_diagnostics "-recovery-failed"
  else
    app_apk="app/build/outputs/apk/offline/debug/app-offline-debug.apk"
    test_apk="app/build/outputs/apk/androidTest/offline/debug/app-offline-debug-androidTest.apk"
    if [[ ! -s "$app_apk" || ! -s "$test_apk" ]]; then
      echo "Prebuilt instrumentation artifacts missing; cannot run direct ADB fallback."
    elif timeout 180s adb -s "$DEVICE_SERIAL" install -r -t "$app_apk" &&
         timeout 180s adb -s "$DEVICE_SERIAL" install -r -t "$test_apk"; then
      instrument_log="$DIAGNOSTICS_DIR/instrumentation-api36.log"
      timeout 600s adb -s "$DEVICE_SERIAL" shell am instrument -w -r \
        "${instrument_fixture_args[@]}" \
        com.vibesync.antivirus.debug.test/androidx.test.runner.AndroidJUnitRunner \
        2>&1 | tee "$instrument_log"
      instrument_status=${PIPESTATUS[0]}
      # Both a nonzero executed test count and the AndroidJUnitRunner success code are mandatory.
      # Do not treat "no compatible devices" or zero tests as success.
      if [[ "$instrument_status" -eq 0 ]] &&
         grep -Eq 'OK \([1-9][0-9]* tests?\)' "$instrument_log" &&
         grep -Eq 'INSTRUMENTATION_CODE: -1' "$instrument_log" &&
         ! grep -Eq 'FAILURES!!!|INSTRUMENTATION_FAILED|INSTRUMENTATION_ABORTED|Process crashed|FAILURE:' "$instrument_log"; then
        echo "API 36 instrumented test suite executed successfully using prebuilt APKs."
        test_status=0
      else
        echo "API 36 instrumentation did not report a verified passing test suite."
      fi
    else
      echo "ADB APK install failed; preserving the original instrumented test failure."
    fi
  fi
fi

capture_diagnostics
timeout 15s adb -s "$DEVICE_SERIAL" shell run-as com.vibesync.antivirus.debug \
  cat files/quarantine-roundtrip-diagnostics.txt \
  > "$DIAGNOSTICS_DIR/quarantine-roundtrip.txt" 2>&1 || true
timeout 15s adb -s "$DEVICE_SERIAL" shell run-as com.vibesync.antivirus.debug \
  cat files/safemobile_private_text_diagnostics.txt \
  > "$DIAGNOSTICS_DIR/private-text.txt" 2>&1 || true

exit "$test_status"
