# Phase F: verified research ML candidate

- Android retrieves the approved **v1.0.1-model** assets from the separate Drebin ML repository at build time using the Gradle `:app:downloadMlAssets` task.
- The release's `malware_model.tflite` asset is renamed locally to `app/src/main/assets/model.tflite`; `feature_schema.json` retains its published name. Neither file is committed to the Android app repository. Both local workspace paths are in `.gitignore`.
- Gradle verifies the exact model size (18,584 bytes), TensorFlow Lite `TFL3` header, model SHA-256 `8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061`, and ordered schema SHA-256 `ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac`. A missing or mismatched download fails the build before Android `preBuild`.
- The old 32-input 912-byte dummy model is not packaged. The approved bundle is a trained 215-feature research candidate. Its reported **97.450034% historical Drebin holdout accuracy** is a dataset-specific research result, not a claim of SafeMobile true-positive rate or contemporary Android malware detection.
- The metadata safety gate is mirrored in `MachineLearningScanner`: `trained=true`, `dummy_untrained=false`, `validated=false`, `production_ready=false`, `status=research_candidate`. Research-only benchmark inference is gated separately; production scanning remains disabled until independent APK/feature-extractor evaluation, threshold calibration, and sign-off are completed.
- The TFLite inference path consumes `[1, 215]` FLOAT32 and returns `[1, 1]` FLOAT32; it verifies the same release SHA-256 at runtime. No APK code is executed and no model request occurs at runtime.
- Ownership/provenance: [v1.0.1-model release](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/tag/v1.0.1-model). Model/data provenance and applicable third-party data rights are in its release `DATASET_NOTICE.md` and [dataset terms](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/blob/main/docs/DATASET_NOTICE.md). This model is NOT represented as SafeMobile proprietary invention.

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

The Gradle task runs automatically before `preBuild`; the explicit task above is useful when validating the release bridge separately. These downloads are build-time retrieval of public, immutable ML release assets only. The installed app performs local inference and does not download models or upload APKs as part of scanning.
