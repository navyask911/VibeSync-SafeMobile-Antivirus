# Offline Malware Risk Model Card

**Status: RESEARCH CANDIDATE — UNVALIDATED; PRODUCTION USE NOT APPROVED.** Reviewed 2026-11-29.

## Readiness state

The Kotlin source constants in `MachineLearningScanner` are the runtime source of truth:

- `MODEL_STATUS = "research_candidate"`
- `MODEL_TRAINED = true`
- `MODEL_VALIDATED = false`
- `MODEL_PRODUCTION_READY = false`
- `MODEL_DUMMY_UNTRAINED = false`

The production-readiness gate remains closed. The explicit research path may be used for controlled, local validation; artifact integrity and tensor compatibility do not change the readiness flags. Do not describe this model as validated, production-ready, or approved for security decisions.

## Intended use and verdict policy

The pinned Drebin-215 bundle is retained as an immutable research reference for controlled evaluation. A probability collected by a research or validation path is advisory only. Model output alone must never trigger uninstall, quarantine, blocking, or a definitive malware claim.

The separate activation document, [ML_MODEL_ACTIVATION.md](ML_MODEL_ACTIVATION.md), describes the current application integration and the approval gates. Existing exact-hash and conclusive YARA detections retain their established precedence. The current fusion policy does not allow ML alone to create a definitive `THREAT`; a high ML score can contribute only when qualifying independent YARA evidence is also present.

- The model bundle's reported threshold is **0.5**. It is publisher metadata, not the app's final verdict threshold.
- The app's ensemble uses **0.65** as the ML-only advisory `SUSPICIOUS` review floor.
- A score **greater than 0.70** requires qualifying YARA evidence before it can contribute to an ensemble `THREAT`.
- A single low-severity YARA match is retained as evidence but does not independently create `SUSPICIOUS`; the existing multi-match and severity rules remain unchanged.

## Artifact and runtime contract

- Source repository: [SafeMobile ML research repository](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware).
- Immutable reference release: [`v1.0.1-model`](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/tag/v1.0.1-model), tag commit `2ba34602a344183313ac9fb8b6fe2f9060a1b7a6`.
- Artifact: `malware_model.tflite`; Android runtime filename: `model.tflite`.
- Artifact size: **18,584 bytes**.
- Model SHA-256: `8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061`.
- Ordered feature metadata: `feature_schema.json`, 215 entries keyed `"0"` through `"214"`.
- Schema SHA-256: `ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac`.
- Tensor contract: **[1, 215] FLOAT32 input → [1, 1] FLOAT32 probability output**.

The Gradle build bridge retrieves the model and schema from the separate repository and verifies their pinned size, digest, flatbuffer header and tensor contract. These checks establish artifact integrity and runtime compatibility only; they do not establish feature-extractor parity, classifier efficacy on contemporary APKs, or production readiness. The model binary is not committed to this Android repository.

## Evaluation results: keep the reference distinct from experiments

### Published reference bundle

The immutable `v1.0.1-model` release reports **97.450034% historical accuracy** on its fixed Drebin holdout (1,414 correct predictions out of 1,451 rows). This is a dataset-specific reference result. It is not a current candidate result, an Android APK-parity score, a measured SafeMobile TPR/FPR, a contemporary-malware evaluation, or independent production certification.

### Unpromoted candidates and ablations

- The 28 November 2026 scheduled candidate measured **96.829773%** on the 1,451-row fixed holdout. It was **REJECTED** because it fell below the promotion floor; publication was skipped and the immutable reference bundle was retained. See [the workflow result](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/actions/runs/46119426853).
- The separate draft validation work records exploratory training ablations, including some trial results above the numeric floor. Those trials are experimental results, not a new approved release or a validated Android classifier. A trial score does not promote its model, satisfy paired-APK parity, establish device performance, or change the Kotlin readiness flags. See [the controlled-ablation report](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/blob/validation/2026-11-28-ablation-harness/docs/CONTROLLED_ABLATION_RESULTS_2026-11-28.md).

The ML repository's `MIN_ACCURACY = 0.9745` (**97.45%**) fixed-holdout floor and `scripts/quality_gate.py` remain the promotion controls. The floor must not be lowered or bypassed. A completed workflow may intentionally retain the previous release when a candidate is rejected; workflow success alone is not evidence that the model passed promotion.

## Production-readiness blockers

Do not change `MODEL_VALIDATED` or `MODEL_PRODUCTION_READY` to true, or change `MODEL_STATUS` from `research_candidate`, until the following evidence is complete, reviewed and approved:

1. **API 35 emulator coverage.** The standard Android CI emulator matrix covers API 26, 28, 33, 34 and 36, not API 35. The dedicated Drebin validation workflow adds an API 35 emulator run; that run must complete successfully. Emulator fixtures and tensor compatibility are not substitutes for physical-device testing.
2. **Real paired-APK parity.** No qualifying real APK corpus comparison has yet established feature-by-feature equality between the independent reference extractor and the Android extractor. A reproducible pilot must include at least 100 benign and 100 malware-source APKs, exact APK SHA-256 joins, per-feature comparison and explicit multidex/base/split-APK results. Synthetic schema fixtures and reference-parser API tests do not establish APK-level parity.
3. **Physical-device performance and stability.** Representative physical Android devices and relevant OEMs (including ColorOS/Oplus) must be measured across supported API levels for extraction and inference latency, PSS/RSS and native/Java heap, repeated-run stability, thermal behavior and battery impact. Emulator timing is not physical-device evidence.
4. **Fixed-holdout and independent efficacy gates.** Any proposed candidate artifact must meet or exceed the unchanged **97.45%** fixed-holdout floor under the pinned evaluation contract. Independent contemporary evaluation must also assess false positives, per-family behavior, calibration and confidence intervals before efficacy claims or production approval.
5. **Dataset suitability and review.** MH-1M and LAMDA remain research-only sources, and McNdroid's unresolved feature mapping prevents it from serving as completed 215-feature production evidence. Do not represent these datasets as passed validation gates.

Until every applicable gate is satisfied, keep the model labelled `research_candidate`, with `MODEL_VALIDATED=false` and `MODEL_PRODUCTION_READY=false`. Existing hash matching, YARA detection, scan-completion semantics and fail-closed handling for unavailable or invalid ML data remain authoritative.

## Privacy and provenance

No APK code is executed for static feature extraction. APK samples, per-sample vectors and package identifiers used during validation must remain in private, app-scoped or otherwise access-controlled storage and must not be committed to the repository or uploaded as CI artifacts. Only explicitly sanitized aggregate summaries may be shared. Scan contents are not uploaded for model inference.

The model bundle is retrieved from the separate [`v1.0.1-model` release](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/tag/v1.0.1-model). See its [`DATASET_NOTICE.md`](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/blob/main/docs/DATASET_NOTICE.md) and dataset terms for source and licensing provenance. The model is not represented as a SafeMobile proprietary invention.
