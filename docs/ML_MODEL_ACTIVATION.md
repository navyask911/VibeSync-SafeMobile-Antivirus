# ML activation gate — research release versus Android production model

The app currently ships a deliberately untrained 32-feature TFLite fixture. MachineLearningScanner has an offline 215-feature APK parser and real TensorFlow Lite Interpreter inference path, but it runs predictions **only** when signed-in-app metadata and the bundled model agree on 215 feature names, float32 tensor shapes, SHA-256 and production readiness.

An existing external release named **v1.0.1-model** in the separate ML repository contains a 215-feature research model. Its README defines **97.45%** as the required promotion gate for a *real fixed Drebin holdout*. A research holdout accuracy is not proof of current-APK on-device TPR, zero-day detection or production readiness. The ML source explicitly instructs maintainers not to mark its research bundles production-ready before independent APK validation.

SafeMobile does **not** fake readiness by changing dummy_untrained to trained or production_ready to true. The bundled fixture is still disabled. This is not an ML-enabled release yet.

To enable the research model safely in a later review, compare the exact release checksums (model, schema, report), confirm the model uses float32 [1,215] input and [1,1] output, validate the app's DrebinApkExtractor output on independently labeled actual APKs, measure TPR and FPR for the intended threshold, perform external benign false-positive review, sign and bundle the correct TFLite model, and only then update trained / validated / production_ready and model_sha256 to factual validated values.

The Phase F 200-APK pilot measures **current production scanner behavior** and separately reports how many samples received an ML score; it must not represent a model-training metric as a measured detection result.
