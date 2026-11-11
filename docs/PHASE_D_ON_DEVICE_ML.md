# Phase D — On-device static machine learning (v1.0.15)

## Safety and claims

This branch implements **offline inference infrastructure**, not a validated zero-day malware detector. Static feature classification is not runtime behavior analysis and cannot establish 80% detection strength without independent held-out evaluation. Do not describe this version as reaching a measured detection rate. No scanned data leaves the device. YARA, hashes and existing heuristics run unchanged when ML is unavailable or fails.

`app/src/main/assets/malware_model.tflite` is a tiny **untrained random-weight** TensorFlow Lite fixture for integration testing only, not a detection model. `malware_model.json` marks it `trained=false`, `validated=false`, and `status=dummy_untrained`; the Android scanner refuses to run this model.

The UI's ML layer reports **Disabled** with the existing localized explanation until an independently validated trained model and matching manifest are shipped. The **Enabled** status, scored result and advisory `ML_HEURISTIC_HIGH` finding appear only after that gate passes and inference succeeds. The score is advisory and **never a confirmed signature hit**.

## Train locally (never in GitHub Actions)

Obtain licensed, vetted, labeled static feature exports (for example, with authorization from CICMalDroid 2020); do not commit APKs, sample data or download tokens. The Drebin raw sample collection requires requesting access from its authors. Review data provenance and commercial/redistribution rights independently.

Install the trainer's pinned dependencies in a disposable, isolated local environment, then run:

```sh
python -m pip install "tensorflow==2.17.0" "scikit-learn>=1.5,<1.7" "numpy<2"
python scripts/train_ml_model.py \
  --csv /private/datasets/verified-android-static-features.csv \
  --dataset-name "Licensed dataset name and date" \
  --license-note "Exact rights, source, and approval" \
  --output app/src/main/assets/malware_model.tflite
```

The training script expects a binary `label` and all 32 named feature columns from its `FEATURES` list, containing 0/1 values. It uses stratified train/validation/test splits with a deterministic seed and exports a float32 `[1,32]` input to float32 `[1,1]` sigmoid output. It records held-out AUC, precision and recall at a 0.85 threshold and writes a JSON manifest with the model SHA-256. The trained artifact is *not* automatically activated.

Review class balance, dataset drift, API version coverage, false positives on ordinary apps, and calibration using a distinct externally validated test set; compare model outputs against the original Python classifier. Only after independent validation, legal review, and owner approval may a separate reviewed commit set `validated=true` and `status=validated_production`, keeping the exact model digest, full ordered feature list, and correct schema. Never mark the random-weight fixture validated.

## Extractor limitations

Android extracts permission flags from PackageManager package metadata; it reads only a bounded set of strings from the APK's binary manifest and DEX contents. Manifest intent-action *string evidence* is not necessarily proof of a registered intent filter. API string evidence is not full bytecode disassembly. APK size, entry count, decoded byte budget and elapsed-time limits bound work. Obfuscation, multidex beyond budget, native code and dynamic loading may evade it; these limitations must be reflected in model evaluation.

Timeout, missing assets, digest mismatch, wrong tensor shape, TFLite runtime error, or corrupt files make the ML result absent without blocking the existing engines. Inference runs on Dispatchers.IO. Neither inference nor training invokes an external service.

## License provenance

TensorFlow Lite Android 2.17.0 was already included in the project dependencies prior to this branch. Follow its upstream Apache-2.0 notices. The demo weights are generated locally and no external dataset or third-party malware sample is redistributed. Include any future training data and model provenance in the legal review before distribution.
