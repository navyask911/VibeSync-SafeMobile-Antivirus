# SafeMobile Detection Engine

## Architecture and scan order

SafeMobile performs its core detection on the device in three ordered layers. The scanner reads package metadata and hashes first; it never executes APK code.

1. **Hash engine — exact signature match.** The file is hashed locally (SHA-256, with supported secondary digests). Exact candidates are verified against the local signed hash database, local encrypted threat store, and the bundled signature set. A confirmed exact hash hit short-circuits the scan: YARA and ML are not run. Its original provenance label is retained (`HASH`, `SIGNED_DATABASE`, or the separately enabled `THREAT_INTELLIGENCE_FEED` source).
2. **YARA engine — static rule inspection.** When no exact hash hit exists, the pinned YARA-X native engine scans supported APK content and DEX/manifest structures using the locally installed rule set. A conclusive YARA threat match returns immediately. Suspicious rule matches are retained as a raw `yaraVerdict` for fusion; an unavailable or incomplete YARA pass is not treated as a clean YARA result.
3. **ML engine — Drebin-215 research/advisory signal.** When the hash and YARA layers have not produced a conclusive threat, the app extracts the fixed 215-element binary feature vector locally and obtains a probability from the SHA-pinned TensorFlow Lite research bundle. The model consumes `[1, 215]` FLOAT32 and emits `[1, 1]` FLOAT32. This is not an independently validated production classifier; it supplies an advisory probability to fusion only. No APK code is executed and inference does not call a network service.

The ensemble evaluator runs after the completed YARA and ML signals are available. Exact hash matches and conclusive YARA matches remain short-circuits, before the more expensive later layers. Existing heuristic-only review findings, user trust decisions, and incomplete scans remain distinct from an ensemble clean result.

## Ensemble decision matrix

The current `ThreatEnsembleEvaluator` applies the following precedence to a completed result:

| Priority | Condition | Final verdict | Source |
|---|---|---|---|
| 1 | Exact SHA-256 match from the local hash, signed database, or explicitly enabled threat-intelligence feed | `THREAT` | Original exact-hash source |
| 2 | Conclusive YARA threat match | `THREAT` | `YARA` |
| 3 | Qualifying YARA evidence **and** finite `mlProbability > 0.70` | `THREAT` | `ENSEMBLE` |
| 4 | Qualifying YARA evidence **or** finite `mlProbability >= 0.65` | `SUSPICIOUS` | `ENSEMBLE` |
| 5 | No qualifying hash, YARA, ML, or preserved heuristic signal | `NO_MATCH` | `NONE` |

A qualifying YARA signal is at least one medium/high severity YARA finding or at least two low-severity YARA findings. A single low-severity YARA finding is retained as evidence but does not influence the fused verdict. The strict greater-than boundary applies to YARA-supported ML threat escalation: `0.70` does not qualify, while a finite score greater than `0.70` does.

The model alone can raise a result only to `SUSPICIOUS`; it cannot create a definitive `THREAT`. Exact hash matches and conclusive YARA threats retain precedence. Model scores for system apps and Google Play Services are ignored. `NOT_SCANNED` and user-trusted results are preserved, and an independent `HEURISTIC` suspicious finding is not rewritten as clean.

Confidence is the deterministic weight shown for the winning rule path. It is not a calibrated probability of infection and must not be presented as an independently measured detection rate.



## Model status and limitations

- Android handoff: immutable **`v1.0.1-model`** at tag commit `2ba34602a344183313ac9fb8b6fe2f9060a1b7a6`.
- Model SHA-256: `8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061` (**18,584 bytes**).
- Ordered schema SHA-256: `ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac` (**215 keys, "0"–"214"**).
- Tensor contract: `[1, 215]` FLOAT32 input and `[1, 1]` FLOAT32 output.
- Readiness metadata: `trained=true`, `validated=false`, `production_ready=false`, `status=research_candidate`.

The published model report's **97.450034% historical Drebin holdout accuracy** is a dataset-specific research result, not an independent contemporary Android malware evaluation, SafeMobile TPR/FPR, calibration study, or zero-day guarantee. The separate ML promotion floor remains **97.45%**. Scheduled run [#46119426853](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/actions/runs/46119426853) measured **96.829773%** on the fixed 1,451-row holdout and rejected its candidate; publication was skipped and the pinned `v1.0.1-model` handoff was retained.

Feature-extractor parity between the Android and training implementations, representative live-device inference latency/peak-memory measurements, and independent current-dataset evaluation remain open gates. Schema order, SHA integrity, tensor compatibility and emulator tests do not close those gates. Keep `production_ready=false` until every required gate has evidence and approval.

The legacy report threshold of **0.5** is bundle metadata. The app currently uses **0.65** as its ML-only suspicious review floor and requires qualifying YARA support plus a score greater than **0.70** for ensemble threat escalation. Neither is a standalone model verdict.



## Privacy boundary

Core scanning, hash comparison, YARA inspection, feature extraction and TFLite inference run locally. They do not upload APK bytes or scan verdicts. Optional signed definition/model downloads and user-initiated billing are separate network operations.

The separately disclosed Global Threat Intelligence contribution feature is opt-in and requires an explicit user action for an eligible detected APK. It sends only the sample SHA-256 digest and 215 binary behavioral features to the designated worker; it does not upload APK bytes, file paths, package names, scan history or device identifiers. Network providers can still process ordinary connection metadata. This contribution is not required for a local scan.



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
