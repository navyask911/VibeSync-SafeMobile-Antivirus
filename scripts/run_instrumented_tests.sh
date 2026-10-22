#!/usr/bin/env bash
# Wait for the Android framework (especially PackageManager) to become responsive before
# invoking Gradle. sys.boot_completed alone is not sufficient on slow/headless API 30+ AVDs.
set -uo pipefail

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

# Keep Gradle's parallel work bounded while the emulator is running to reduce VM memory pressure.
./gradlew --no-daemon --max-workers=2 --no-parallel \
  -Dorg.gradle.jvmargs="-Xmx2g -Dfile.encoding=UTF-8" \
  connectedOfflineDebugAndroidTest
test_status=$?

capture_diagnostics
timeout 15s adb -s "$DEVICE_SERIAL" shell run-as com.vibesync.antivirus.debug \
  cat files/quarantine-roundtrip-diagnostics.txt \
  > "$DIAGNOSTICS_DIR/quarantine-roundtrip.txt" 2>&1 || true
timeout 15s adb -s "$DEVICE_SERIAL" shell run-as com.vibesync.antivirus.debug \
  cat files/safemobile_private_text_diagnostics.txt \
  > "$DIAGNOSTICS_DIR/private-text.txt" 2>&1 || true

exit "$test_status"
