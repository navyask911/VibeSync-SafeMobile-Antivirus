# Drebin-215 Device Validation Harness

The instrumentation collector is intentionally isolated under androidTest and does not change production scanning, verdicts, model assets, or model thresholds.

## What it measures

Run DrebinDeviceValidationHarnessTest on the exact app build under test. It verifies the packaged schema and approved TFLite asset SHA-256, executes positive and negative observation fixtures directly against the Kotlin 215-feature contract, parses a harmless synthetic binary AndroidManifest, checks malformed/missing manifest, missing-DEX and malformed-ZIP outcomes, and probes DEX extraction on the installed app APK. It then measures:
- model asset read and hash verification;
- cold Interpreter construction and tensor allocation;
- repeated invoke-only timing on one retained Interpreter;
- the current TfliteInferenceEngine path, which creates and closes an Interpreter on every call;
- DrebinApkExtractor timing and extraction-plus-inference timing for locally supplied APKs;
- PSS, native heap, Java heap and device memory snapshots.

The test runs 30 asset-read/hash and cold Interpreter-init repetitions, 1,000 retained-Interpreter invocations and 300 production-path calls. It captures memory snapshots before production inference and at 1, 10, 50 and 300 calls. The report stores p50/p95/p99, mean, standard deviation, min and max. The APK result section contains full 215-bit vectors and must remain private. The test does not install or execute the supplied APKs. It also records installed-package base/split APK component vectors independently and reports feature indices found only in split APKs relative to the base APK; this is diagnostic only and does not change production ML behavior.

## Build and run

Use a physical Android device with USB debugging and an API level appropriate to the validation matrix. The debug variant uses package ID com.vibesync.antivirus.debug.

Linux/macOS:

~~~bash
./gradlew :app:assembleOfflineDebug :app:assembleOfflineDebugAndroidTest
adb install -r app/build/outputs/apk/offline/debug/app-offline-debug.apk
adb install -r app/build/outputs/apk/androidTest/offline/debug/app-offline-debug-androidTest.apk
adb shell mkdir -p /sdcard/Android/data/com.vibesync.antivirus.debug/files/drebin-validation/apks
adb push /secure/private-apks/sample.apk /sdcard/Android/data/com.vibesync.antivirus.debug/files/drebin-validation/apks/
adb shell am instrument -w \
  -e appCommit <40-character-source-sha> \
  -e runPackageScanner true \
  -e packageScanLimit 10 \
  com.vibesync.antivirus.debug.test/androidx.test.runner.AndroidJUnitRunner
adb pull /sdcard/Android/data/com.vibesync.antivirus.debug/files/drebin-validation/results/drebin-device-validation.json ./drebin-device-validation.json
adb shell run-as com.vibesync.antivirus.debug cat files/drebin-validation-summary.json > ./drebin-device-validation-summary.json
~~~

Windows PowerShell: use .\gradlew.bat and the same adb subcommands. Keep APK files and the full per-APK JSON outside Git. The internal `drebin-validation-summary.json` file omits per-APK vectors and package names; CI collects only this sanitized aggregate file.

The synthetic parser fixtures do not substitute for real DEX corpus coverage. For real APK parity, push at least 100 benign and 100 malware-source APKs with documented provenance; include single-DEX, multidex and base/split APK samples where available. Avoid samples that the test team is not authorized to store or process. The instrumentation test processes at most 100 APK files in one run; use several disjoint batches and merge the private JSON outputs by APK SHA-256.

## CI status

The validation branch includes an API 35 x86_64 emulator workflow that compiles and executes the instrumentation test and uploads only the sanitized summary artifact. It validates Kotlin feature mapping, synthetic binary-manifest/ZIP/DEX cases, packaged model inference and aggregate timing/report generation. Emulator timing numbers, if collected, are not substitutes for physical-device measurements and are not to be combined with the API 26 / 33–34 / 36 hardware matrix.

## Device matrix and interpretation

Repeat on API 26, API 33/34 and API 36 hardware, including ColorOS/Oplus and a Pixel-class reference. Record starting battery, ambient/device temperature, charging state, screen/radio settings and thermal status externally. Run each device at least three times after cooling; do not merge emulator and physical-device samples into one latency distribution.

The extract_plus_inference_latency metric is APK extraction plus model inference only. An optional package_scanner_benchmark separately measures the production PackageScanner.scanInstalledPackage path with its YARA, hash, static-analysis and ML stages. It runs sequentially for up to 10 installed third-party apps, twice each, using an in-memory Room database; the normal test run skips it. It is not a full-device concurrent scanInstalledAppsForSession duration. App process cold-start time, UI latency, battery drain and thermal throttling require separately instrumented test scenarios.

No physical Android device is attached to the repository validation runner. Therefore no physical-device timing or memory result is claimed until the artifact from this test has actually been collected from hardware.
