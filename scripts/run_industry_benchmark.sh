#!/usr/bin/env bash
# Run benchmark against real, SHA-pinned APK bytes. Neither Android permission
# escalation nor an external-storage grant is needed: run-as stages files with
# the debug application's own UID in its app-specific external files directory.
set -euo pipefail
root="${RUNNER_TEMP:?}/industry"
app_id="com.vibesync.antivirus.debug"
target="/sdcard/Android/data/$app_id/files/industry-benchmark"
mkdir -p "$root/results"

adb install -r app/build/outputs/apk/offline/debug/app-offline-debug.apk
test_apk="$(find app/build/outputs/apk/androidTest -name '*androidTest.apk' -print -quit)"
test -s "$test_apk"
adb install -r "$test_apk"

# The APK is a debuggable build. run-as ensures staged data is written by the
# SAME Linux app UID that the instrumentation target uses to read it. Plain
# 'adb push' creates shell-owned files and led to EACCES on API 33.
adb shell run-as "$app_id" mkdir -p "$target"

stage_as_app_uid() {
  local host_file="$1"
  local name="${host_file##*/}"
  [[ "$name" == "batch.json" || "$name" =~ ^[bm][0-9]{4}\.apk$ ]] || {
    echo "Rejected unexpected staged filename: $name" >&2
    return 1
  }
  # -T suppresses the adb PTY, so APK bytes are copied without transformations.
  # Quoted remote sh -c redirection executes AS the app UID, not as shell.
  adb shell -T "run-as $app_id sh -c 'cat > $target/$name'" < "$host_file"
  local expected actual
  expected="$(sha256sum "$host_file" | cut -d' ' -f1)"
  actual="$(adb exec-out run-as "$app_id" sha256sum "$target/$name" | tr -d '\r' | cut -d' ' -f1)"
  if [[ "$actual" != "$expected" ]]; then
    echo "SAFE STOP: staged file SHA-256 mismatch or unreadable by app: $name" >&2
    return 1
  fi
}

# Check actual write AND read permission before downloading real APKs.
probe="$(mktemp)"
printf 'SafeMobile benchmark app-UID storage preflight\n' > "$probe"
adb shell -T "run-as $app_id sh -c 'cat > $target/permission-probe.txt'" < "$probe"
adb exec-out run-as "$app_id" cat "$target/permission-probe.txt" | cmp - "$probe"
rm -f "$probe"
adb shell run-as "$app_id" rm -f "$target/permission-probe.txt"
echo "Private-to-app benchmark file handoff verified; no storage permission required."

# The app must be offline for detection; the host still downloads APK corpus
# files and checks SHA-256 before staging them into app-specific storage.
adb shell svc wifi disable || true
adb shell svc data disable || true
cleanup() {
  rm -rf "$root/corpus"
  adb shell run-as "$app_id" rm -rf "$target" || true
}
trap cleanup EXIT
for offset in $(seq 0 10 190); do
  python3 scripts/industry_benchmark.py stage --plan "$root/plan.json" --root "$root/corpus" --offset "$offset"
  adb shell run-as "$app_id" mkdir -p "$target"
  for file in "$root/corpus/"*; do
    [[ -f "$file" ]] || { echo "Missing staged APK/manifest" >&2; exit 1; }
    stage_as_app_uid "$file"
  done
  # Execute only the isolated read-only industry test. Every one of the 10
  # sample digests must match its pinned manifest inside the instrumentation.
  adb shell am instrument -w -r -e class \
    com.vibesync.antivirus.core.engine.IndustryBenchmarkInstrumentedTest#scanBatch \
    com.vibesync.antivirus.debug.test/androidx.test.runner.AndroidJUnitRunner > "$root/scan.log"
  if ! grep -q 'OK (1 test)' "$root/scan.log" || ! grep -q 'INSTRUMENTATION_CODE: -1' "$root/scan.log"; then
    cat "$root/scan.log" >&2
    echo "SAFE STOP: Android did not confirm passing benchmark instrumentation" >&2
    exit 1
  fi
  # Read result as the app's own UID, not with ADB pull against protected dirs.
  adb exec-out run-as "$app_id" cat "$target/batch-results.json" > "$root/results/batch-$offset.json"
  python3 - "$root/results/batch-$offset.json" <<'PY'
import json,sys
from pathlib import Path
file=Path(sys.argv[1])
rows=json.loads(file.read_text(encoding="utf-8")).get("samples")
assert isinstance(rows,list) and len(rows)==10, "Missing/incomplete on-device batch"
assert all(isinstance(s,dict) and s.get("sha256") and
           isinstance(s.get("duration_ms"),(int,float)) for s in rows), "No real scan evidence"
print("Validated 10 actual on-device scan records",flush=True)
PY
  rm -rf "$root/corpus"
  adb shell run-as "$app_id" rm -rf "$target"
  echo "Actual read-only scans completed: $((offset+10))/200" 
done
