# Offline Malware Risk Model Card

**Status: DISABLED — no trained model is shipped.** Reviewed 2026-10-24. No accuracy, TPR, FPR, precision, recall or inference-latency result is claimed.

## Intended use

A future local model may provide supplementary APK triage from manifest/permission/API-call features and optional DEX-string hashes. Model output must never be the sole basis for an uninstall, quarantine, blocking action, or definitive malware claim.

## Artifact and training data

- Model artifact: none. `app/src/main/assets/malware_model.tflite` is absent.
- Runtime behavior: `OfflineTfliteClassifier.classify` returns `enabled=false`, `riskScore=null`, and a stable disabled reason. It never fabricates a prediction.
- Dataset: NOT SELECTED FOR TRAINING. MH-100K/MH-1M access, exact revision, labels, redistribution terms, binary/sample access and train/test split have not been verified for a legally redistributable model build.
- Architecture, weights, quantization, feature mapping, threshold, calibration and label provenance: NOT APPLICABLE because no model is selected or trained.

## Evaluation metrics

- Accuracy: NOT MEASURED — there is no trained model artifact.
- TPR / recall: NOT MEASURED — there is no trained model artifact.
- FPR: NOT MEASURED — there is no trained model artifact and no thresholded evaluation run.
- Precision: NOT MEASURED — no held-out labeled evaluation corpus was run.
- Inference latency and additional memory: NOT MEASURED — no model is loaded or executed.

These are absences of measurements, not zero rates and not guarantees of correctness.

## Evaluation protocol required before enabling

Select a legally distributable, versioned training corpus and retain dataset citations and license terms. Use family/source/time-grouped splits to reduce leakage. Document class balance and label provenance. Evaluate on held-out malicious and benign samples, report threshold-specific TPR/FPR/precision/recall with confidence intervals, calibration, per-family/source performance, inference latency and peak incremental memory on named reference hardware. Compare the false-positive burden on at least 1,000 legally sourced benign APKs. Keep an immutable reproducible training/evaluation script and artifact hash.

## Known limitations and bias risks

Permission-only models risk conflating app category with maliciousness and may over-flag assistive, security, automation, accessibility or enterprise apps. App source, language, SDK age, family prevalence and class imbalance can skew labels. Models may miss new families and packed/reflected/native implementations. Any future model should be advisory and explain feature groups without exposing sensitive user data.

## Release policy

Do not ship an empty, placeholder, random-weight or hand-crafted tensor as a trained classifier. Do not download a model unless redistribution rights, provenance, signature/integrity and compatibility are verified. The engine remains DISABLED until a real trained artifact and evaluation report are independently reviewed.