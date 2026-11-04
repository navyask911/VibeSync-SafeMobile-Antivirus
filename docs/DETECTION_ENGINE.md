# SafeMobile Detection Engine

## Architecture and scan order

SafeMobile performs its core detection on the device in three ordered layers. The scanner reads package metadata and hashes first; it never executes APK code.

1. **Hash engine — exact signature match.** The file is hashed locally (SHA-256, with supported secondary digests). Exact candidates are verified against the local signed hash database, local encrypted threat store, and the bundled signature set. A confirmed exact hash hit short-circuits the scan: YARA and ML are not run. Its original provenance label is retained (`HASH`, `SIGNED_DATABASE`, or the separately enabled `THREAT_INTELLIGENCE_FEED` source).
2. **YARA engine — static rule inspection.** When no exact hash hit exists, the pinned YARA-X native engine scans supported APK content and DEX/manifest structures using the locally installed rule set. A conclusive YARA threat match returns immediately. Suspicious rule matches are retained as a raw `yaraVerdict` for fusion; an unavailable or incomplete YARA pass is not treated as a clean YARA result.
3. **ML engine — Drebin-215 static features.** When the hash and YARA layers have not produced a conclusive threat, the app extracts the fixed 215-element binary feature vector locally and runs the committed TensorFlow Lite model. The model consumes `[1, 215]` FLOAT32 and emits `[1, 1]` FLOAT32. No APK code is executed and inference does not call a network service.

The ensemble evaluator runs after the completed YARA and ML signals are available. Exact hash matches and conclusive YARA matches remain short-circuits, before the more expensive later layers. Existing heuristic-only review findings, user trust decisions, and incomplete scans remain distinct from an ensemble clean result.

## Ensemble decision matrix

The following precedence is applied to a completed result:

| Priority | Condition | Final verdict | Source | Confidence |
|---|---|---|---|---:|
| 1 | `detectionSource == HASH` and verdict is `THREAT` | `THREAT` | `HASH` | 1.0 (100%) |
| 2 | `detectionSource == YARA` and verdict is `THREAT` | `THREAT` | `YARA` | 0.9 (90%) |
| 3 | `yaraVerdict == SUSPICIOUS` and finite `mlProbability > 0.7` | `THREAT` | `ENSEMBLE` | `mlProbability` |
| 4 | `yaraVerdict == SUSPICIOUS` **or** finite `0.4 <= mlProbability <= 0.7` | `SUSPICIOUS` | `ENSEMBLE` | `mlProbability` (0 when the model did not return a probability) |
| 5 | No qualifying Hash, YARA, or ML signal | `NO_MATCH` | `NONE` | 0.0 |

The boundaries are inclusive for the suspicious ML band: 0.40 and 0.70 produce `SUSPICIOUS`; a value greater than 0.70 produces an ensemble `THREAT` only when YARA is also `SUSPICIOUS`. An ML score above 0.70 by itself is not a threat verdict.

Two safety-preserving states are not rewritten by the default: `NOT_SCANNED` stays `NOT_SCANNED`, and a pre-existing independent `HEURISTIC` review finding remains `SUSPICIOUS`. Exact signed-database and explicitly enabled threat-feed hash hits are also preserved as definitive digest detections with their original source labels. These safeguards avoid turning access failures, independent static-review findings, or other verified exact-hash sources into a false clean result.

Confidence is the deterministic weight shown for the winning rule path. It is not a calibrated probability of infection and must not be presented as an independently measured detection rate.

## Model status and limitations

- Model release: **approved `v1.0.1-model`**.
- Reported historical result: **97.45% accuracy on the historical Drebin holdout evaluation**.
- Model metadata intentionally remains **`production_ready: false`** for modern zero-day detection.

The historical holdout result is a dataset-specific evaluation, not an independent test on contemporary Android malware, not a guarantee of real-world performance, and not evidence that the model can detect modern zero-days. The model therefore remains one advisory signal in the ensemble. SafeMobile does not claim zero-day protection or infer that a file is safe solely because the model or local definitions return no match.

## Privacy boundary

All scanning is 100% offline. No user data, APK files, or scan results leave the device.

Hash comparison, YARA scanning, feature extraction, and TensorFlow Lite inference execute locally. Signed definition/model downloads are separate update operations and are not APK uploads or scan submissions. The optional threat-intelligence contribution feature is also separate from scanning: it requires the user to enable the contribution setting and explicitly donate an eligible detected sample. That opt-in request contains only the sample SHA-256 digest and its 215 binary features; it does not upload APK bytes, app/package names, file paths, or device/user identifiers. This optional contribution is not required for any local scan.

## Model checksum verification

The app does not commit the model binary, model metadata JSON, or feature-schema JSON. Gradle's `:app:downloadMlAssets` task retrieves the immutable public `v1.0.1-model` release at build time, writes the model as the local ignored asset `model.tflite`, and writes the ordered schema as `feature_schema.json`. Before Android `preBuild`, it verifies the model size, TensorFlow Lite `TFL3` header, model SHA-256, and schema SHA-256; a mismatch fails the build.

From the repository root:

```bash
sha256sum app/src/main/assets/model.tflite
# expected: 8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061

sha256sum app/src/main/assets/feature_schema.json
# expected: ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac

./gradlew --no-daemon :app:downloadMlAssets
```

The model asset is expected to be 18,584 bytes and to begin with the TensorFlow Lite `TFL3` identifier. The schema digest pins the exact 215-feature ordering used by the extractor. A mismatch fails the build instead of silently accepting a different model or feature contract.

## CI verification

The pinned YARA-X native build is prepared deterministically. `prepareYaraXNativeSource` checks out the immutable JNI source revision and recursive submodules; `prepareYaraXPatches` resets the pinned nested YARA-X checkout, applies the complete checked-in patch set through `make patch`, and verifies required parser/protobuf markers. `buildYaraXNative` depends on that patch task, so restored Gradle caches cannot cause an incomplete native patch set to be compiled.

The Android CI pipeline downloads and verifies the ML release assets before its asset-contract tests, then validates JVM ensemble tests, the Compose UI test, Paparazzi snapshots, lint, offline/feed artifact builds and privacy checks, plus emulator instrumentation on API 26, 33, 34 and 36.
