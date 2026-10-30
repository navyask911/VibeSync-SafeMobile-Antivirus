#!/usr/bin/env bash
set -euo pipefail
root="$RUNNER_TEMP/industry"
target="/sdcard/Android/data/com.vibesync.antivirus.debug/files/industry-benchmark"
adb install -r app/build/outputs/apk/offline/debug/app-offline-debug.apk
test_apk="$(find app/build/outputs/apk/androidTest -name '*androidTest.apk' -print -quit)"
test -n "$test_apk"
adb install -r "$test_apk"
adb shell svc wifi disable || true
adb shell svc data disable || true
trap 'rm -rf "$root/corpus"; adb shell rm -rf "$target" || true' EXIT
for offset in $(seq 0 25 1975); do
  python3 scripts/industry_benchmark.py stage --plan "$root/plan.json" --root "$root/corpus" --offset "$offset"
  adb shell mkdir -p "$target"
  adb push "$root/corpus/." "$target/" >/dev/null
  adb shell am instrument -w -r -e class com.vibesync.antivirus.core.engine.IndustryBenchmarkInstrumentedTest#scanBatch \
    com.vibesync.antivirus.debug.test/androidx.test.runner.AndroidJUnitRunner > "$root/scan.log"
  grep -q 'OK (1 test)' "$root/scan.log" || { cat "$root/scan.log"; exit 1; }
  adb pull "$target/batch-results.json" "$root/results/batch-$offset.json" >/dev/null
  rm -rf "$root/corpus"
  adb shell rm -rf "$target"
  echo "Actual read-only scans completed: $((offset+25))/2000"
done
