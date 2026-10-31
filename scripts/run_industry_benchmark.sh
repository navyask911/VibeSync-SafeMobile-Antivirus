#!/usr/bin/env bash
# 200 real APK files are staged by ADB in /data/local/tmp. The runner then
# copies SHA-256-verified bytes into debug-app-private files via adb run-as,
# keeping production permissions and application assets unchanged.
set -euo pipefail
root="${RUNNER_TEMP:?}/industry"
app_id="com.vibesync.antivirus.debug"
handoff="/data/local/tmp/industry-benchmark"
private="/data/user/0/$app_id/files/industry-benchmark"
mkdir -p "$root/results"

adb install -r app/build/outputs/apk/offline/debug/app-offline-debug.apk
test_apk="$(find app/build/outputs/apk/androidTest -name '*androidTest.apk' -print -quit)"
test -s "$test_apk"
adb install -r "$test_apk"

cleanup() {
  rm -rf "$root/corpus"
  adb shell rm -rf "$handoff" || true
  adb shell run-as "$app_id" rm -rf "$private" || true
}
trap cleanup EXIT

adb shell mkdir -p "$handoff"
adb shell run-as "$app_id" mkdir -p "$private"
# App-private write/read preflight with exact bytes.
probe="$(mktemp)"
printf 'SafeMobile 200-APK private-app handoff\n' > "$probe"
adb shell -T "run-as $app_id sh -c 'cat > $private/permission-probe.txt'" < "$probe"
adb exec-out run-as "$app_id" cat "$private/permission-probe.txt" | cmp - "$probe"
rm -f "$probe"
adb shell run-as "$app_id" rm -f "$private/permission-probe.txt"
echo "Verified /data/local/tmp -> app-private handoff setup."

stage_as_app_uid() {
  local host_file="$1"
  local name="${host_file##*/}"
  [[ "$name" == "batch.json" || "$name" =~ ^[bm][0-9]{4}\.apk$ ]] || {
    echo "SAFE STOP: Unexpected staged filename: $name" >&2
    return 1
  }
  # The shell can read /data/local/tmp; app-private files are written with
  # run-as and are only readable by SafeMobile's own debug UID.
  adb push "$host_file" "$handoff/$name" >/dev/null
  adb exec-out cat "$handoff/$name" |
    adb shell -T "run-as $app_id sh -c 'cat > $private/$name'"
  local expected actual
  expected="$(sha256sum "$host_file" | cut -d' ' -f1)"
  actual="$(adb exec-out run-as "$app_id" sha256sum "$private/$name" | tr -d '\r' | cut -d' ' -f1)"
  if [[ "$actual" != "$expected" ]]; then
    echo "SAFE STOP: app-private APK SHA-256 does not match pinned host copy: $name" >&2
    return 1
  fi
  echo "Verified app-private staged file: $name ($actual)"
}

# APK download occurs on the host only. The device's scanner has no network.
adb shell svc wifi disable || true
adb shell svc data disable || true

for offset in $(seq 0 10 190); do
  python3 scripts/industry_benchmark.py stage --plan "$root/plan.json" --root "$root/corpus" --offset "$offset"
  adb shell mkdir -p "$handoff"
  adb shell run-as "$app_id" mkdir -p "$private"
  for file in "$root/corpus/"*; do
    [[ -f "$file" ]] || { echo "SAFE STOP: Missing APK/manifest" >&2; exit 1; }
    stage_as_app_uid "$file"
  done

  adb shell am instrument -w -r -e class \
    com.vibesync.antivirus.core.engine.IndustryBenchmarkInstrumentedTest#scanBatch \
    com.vibesync.antivirus.debug.test/androidx.test.runner.AndroidJUnitRunner > "$root/scan.log"
  if ! grep -q 'OK (1 test)' "$root/scan.log" ||
     ! grep -q 'INSTRUMENTATION_CODE: -1' "$root/scan.log"; then
    cat "$root/scan.log" >&2
    echo "SAFE STOP: Benchmark instrumentation failed." >&2
    exit 1
  fi

  adb exec-out run-as "$app_id" cat "$private/batch-results.json" > "$root/results/batch-$offset.json"
  python3 - "$root/results/batch-$offset.json" <<'PY'
import json,sys
from pathlib import Path
rows=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")).get("samples")
assert isinstance(rows,list) and len(rows)==10, "Incomplete on-device batch"
assert all(isinstance(x,dict) and x.get("sha256") and x.get("verdict") and
           isinstance(x.get("duration_ms"),(int,float)) for x in rows), "Invalid device scan records"
print("10 real read-only APK scans verified", flush=True)
PY

  rm -rf "$root/corpus"
  adb shell rm -rf "$handoff"
  adb shell run-as "$app_id" rm -rf "$private"
  echo "Actual read-only scans completed: $((offset+10))/200"
done
