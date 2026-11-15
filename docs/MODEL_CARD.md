# Offline Malware Risk Model Card

**Status: ACTIVE — advisory on-device TFLite inference.** Reviewed 2026-11-15.

## Intended use

The pinned Drebin-215 model supplies a supplementary local APK-risk signal. The result is advisory and is fused with independent signals. Model output alone must never trigger an uninstall, quarantine, blocking action, or a definitive malware claim.

## Artifact and runtime contract

- Artifact: immutable `v1.0.1-model`, retrieved at build time from the separate ML repository; the model binary is not committed to this Android repository.
- Runtime filename: `model.tflite`; ordered feature metadata: `feature_schema.json`.
- Model artifact size: 18,584 bytes.
- Model SHA-256: `8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061`.
- Schema SHA-256: `ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac`.
- Tensor contract: `[1, 215]` FLOAT32 input and `[1, 1]` FLOAT32 probability output.
- The build bridge and instrumentation test verify artifact digest, TFL3 header, input/output shapes and tensor types. A bad or missing asset fails verification rather than silently enabling an incompatible model.

## Model status and verdict policy

The app gate is enabled (`active`, `validated=true`, `production_ready=true`, `dummy_untrained=false`). These flags describe the approved artifact and runtime-compatibility gate; they do not imply that contemporary threat efficacy has been measured.

- ML probability below 0.65 does not create an ML suspicious verdict.
- ML probability at or above 0.65 can produce an advisory `SUSPICIOUS` result.
- ML alone cannot create `THREAT`.
- A single low-severity YARA match is retained as evidence but does not independently create `SUSPICIOUS`; at least two low-severity matches are required for that YARA signal. Medium/high YARA findings retain their severity handling.
- Exact known-malware hash matches retain their independent conclusive precedence.

## Evaluation metrics and limitations

The model repository reports 97.450034% accuracy on its historical Drebin holdout. That number is dataset-specific and is not an independently reproduced Android-app benchmark or SafeMobile true-positive rate. Contemporary TPR, FPR, precision, recall, calibration, per-family performance and confidence intervals are not claimed in this app release.

Permission/API features can correlate with legitimate app categories and can over-flag accessibility, security, automation or enterprise apps. Packed, reflected, native and dynamically loaded code may evade static feature extraction. New malware families and dataset drift may reduce effectiveness. Inaccessible, malformed or incomplete APK feature extraction must not be interpreted as an ML clean prediction.

## Privacy and provenance

No APK code is executed. Feature extraction and inference are local; scan contents are not uploaded for model inference. The model bundle is build-time retrieved from the separate [v1.0.1-model release](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/tag/v1.0.1-model). See its `DATASET_NOTICE.md` and [dataset terms](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/blob/main/docs/DATASET_NOTICE.md) for source and licensing provenance. The model is not represented as a SafeMobile proprietary invention.
