#!/usr/bin/env bash
# Run instrumentation and collect diagnostics in the same shell even if Gradle fails.
set +e

./gradlew --no-daemon connectedOfflineDebugAndroidTest
test_status=$?

mkdir -p build/emulator-diagnostics
adb logcat -b all -d -t 30000 > build/emulator-diagnostics/logcat.txt 2>&1 || true
adb shell run-as com.vibesync.antivirus.debug cat files/quarantine-roundtrip-diagnostics.txt > build/emulator-diagnostics/quarantine-roundtrip.txt 2>&1 || true
adb shell run-as com.vibesync.antivirus.debug cat files/safemobile_private_text_diagnostics.txt > build/emulator-diagnostics/private-text.txt 2>&1 || true
adb shell dumpsys package com.vibesync.antivirus.debug > build/emulator-diagnostics/target-package.txt 2>&1 || true
adb shell dumpsys package com.vibesync.antivirus.debug.test > build/emulator-diagnostics/test-package.txt 2>&1 || true

exit "$test_status"
