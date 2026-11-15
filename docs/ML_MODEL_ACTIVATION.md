# Active TFLite model: v1.0.1-model

- Android retrieves the immutable **v1.0.1-model** bundle from the separate Drebin ML repository at build time using Gradle `:app:downloadMlAssets`.
- The published `malware_model.tflite` asset is renamed locally to `app/src/main/assets/model.tflite`; `feature_schema.json` retains its published name. Neither file is committed to the Android app repository. Both local workspace paths are in `.gitignore`.
- Gradle verifies the exact model size (18,584 bytes), TensorFlow Lite `TFL3` header, model SHA-256 `8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061`, and ordered schema SHA-256 `ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac`. A missing or mismatched download fails the build before Android `preBuild`.
- Runtime and CI verification cover the tensor contract `[1, 215]` FLOAT32 input to `[1, 1]` FLOAT32 output. The Android capability gate is `status=active`, `trained=true`, `validated=true`, `production_ready=true`, and `dummy_untrained=false`. Activation means the pinned model and Android inference contract are enabled; it does **not** establish contemporary malware-detection accuracy.
- Model scores are advisory. The ML-only `SUSPICIOUS` threshold is `0.65`; a lower score does not create an ML suspicious verdict. ML alone cannot create a definitive `THREAT` result. The ensemble requires a qualifying YARA signal to escalate a high ML score; a single low-severity YARA match is recorded but ignored for suspicious classification, while two or more low-severity matches may contribute.
- The model's reported **97.450034% historical Drebin holdout accuracy** is a dataset-specific research result from the model project, not a claim of SafeMobile true-positive rate, false-positive rate, or current Android malware detection performance. Contemporary APK metrics, threshold calibration, per-family performance and confidence intervals are not claimed here.
- No APK code is executed and no model request occurs at runtime. Scanning and model inference run locally.
- Ownership/provenance: [v1.0.1-model release](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases/tag/v1.0.1-model). Model/data provenance and applicable third-party data rights are in its release `DATASET_NOTICE.md` and [dataset terms](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/blob/main/docs/DATASET_NOTICE.md). This model is not represented as a SafeMobile proprietary invention.

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
