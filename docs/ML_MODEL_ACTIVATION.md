# Drebin-215 research model and activation gates

## Current status

- **Runtime role:** local research/advisory probability only; not an independently validated production classifier.
- **Metadata gate:** `trained=true`, `validated=false`, `production_ready=false`, `dummy_untrained=false`, `status=research_candidate`.
- **Production ML readiness:** **NOT APPROVED**. The Android production-readiness gate in `MachineLearningScanner` remains closed. Its explicit research path may be used for controlled validation only.
- **Current app behavior:** `PackageScanner` may collect a local TFLite probability through `TfliteInferenceEngine`; `ThreatEnsembleEvaluator` treats that value as advisory. ML alone can only produce `SUSPICIOUS`; it cannot create a definitive `THREAT`. A high score can contribute to `THREAT` only when qualifying YARA evidence is also present. Exact hash and conclusive YARA detections keep their existing precedence.

A verified SHA-256, a valid TFLite flatbuffer, and a matching tensor shape establish **artifact integrity and runtime compatibility only**. They do not establish feature-extractor parity, classifier quality on contemporary APKs, calibration, or production readiness.

## Immutable Android handoff contract

- Source repository: [SafeMobile ML research repository](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware).
- Pinned release: [`v1.0.1-model`](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/tag/v1.0.1-model), tag commit `2ba34602a344183313ac9fb8b6fe2f9060a1b7a6`.
- Model asset: `malware_model.tflite`, **18,584 bytes**, SHA-256 `8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061`.
- Schema asset: `feature_schema.json`, **215 ordered features** keyed `"0"` through `"214"`, SHA-256 `ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac`.
- Tensor contract: **[1, 215] FLOAT32 input → [1, 1] FLOAT32 output**.
- The model report's threshold is **0.5**. This is publisher metadata, not the app's final verdict threshold. The app's ensemble currently uses **0.65** as the ML-only `SUSPICIOUS` review floor and requires a score **greater than 0.70 plus qualifying YARA evidence** for ensemble `THREAT`.
- Gradle downloads the two assets into the ignored local `app/src/main/assets/` workspace and verifies size, TFL3 header, and both SHA-256 pins before `preBuild`. The binaries are not committed to this Android repository.

## Historical result and current promotion gate

The published bundle reports **97.450034% historical accuracy** on its Drebin holdout. That figure is a dataset-specific research result; it is not SafeMobile's measured TPR/FPR, modern Android malware accuracy, independent certification, or evidence of zero-day detection.

The separate ML repository retains `MIN_ACCURACY = 0.9745` (**97.45%**) as its fixed-holdout promotion floor. On 28 November 2026, scheduled run [#46119426853](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/actions/runs/46119426853) measured **96.829773%** on the 1,451-row fixed holdout. Its candidate was **REJECTED**, the quality-gate warning recorded that it was below the 97.45% floor, and publication was skipped. The run's workflow completed because the designed policy retains the currently published model when a candidate only misses the accuracy floor; a successful workflow status does **not** mean the candidate passed promotion.

The rejected 19,768-byte candidate is not the Android handoff and must not replace the pinned 18,584-byte `v1.0.1-model` bundle. The published tag, model bytes and feature schema remain the immutable reference for the existing advisory path; no new model was promoted by that run.

## Production-readiness blockers

Do not set `MODEL_VALIDATED=true`, `MODEL_PRODUCTION_READY=true`, or `production_ready=true` until all required evidence is reviewed and approved:

1. **Holdout gate:** a candidate must meet or exceed the unchanged 97.45% fixed-holdout floor using the pinned dataset/holdout contract; the latest candidate did not.
2. **Extractor parity:** Android's manifest/DEX extractor must be compared feature-by-feature with the training extractor on a fixed, reproducible APK fixture corpus. The 215-key schema pin and unit tests do not prove extractor parity.
3. **Device performance:** representative live Android device measurements must establish end-to-end inference latency, peak memory, stability and timeout behavior across supported API levels and relevant OEMs. CI emulator tensor compatibility is not a substitute.
4. **Independent evaluation:** contemporary and appropriately separated datasets, per-family results, false-positive analysis, threshold calibration and confidence intervals must be reviewed before any production claim.

Until then, keep the model labelled `research_candidate`, `validated=false`, and `production_ready=false`. Existing hash matching, YARA detection, scan completion semantics, and fail-closed model fallbacks remain authoritative.

## Reproduce and verify the build-time download

From the Android repository root:

```bash
./gradlew --no-daemon :app:downloadMlAssets

sha256sum app/src/main/assets/model.tflite
# expected: 8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061

sha256sum app/src/main/assets/feature_schema.json
# expected: ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac

./gradlew --no-daemon clean assembleDebug
```

The build-time bridge verifies the pinned assets and input/output contract. It does not certify the model as production-ready.
