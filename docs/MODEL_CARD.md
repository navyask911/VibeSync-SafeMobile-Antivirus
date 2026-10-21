# Offline Malware Risk Model Card

**Status:** No model is shipped or evaluated as of 2026-10-22.

## Intended use
A future model may provide supplementary triage from app manifest and permission features. It must not be the sole basis for uninstall, quarantine, or a malware claim.

## Model and data
- Model artifact: none; `assets/malware_model.tflite` is absent.
- Architecture, training data, label provenance, splits, quantization and calibration: not applicable until a reproducible model is selected and trained.
- Evaluation dataset and metrics: not available.
- Threshold and expected false-positive rate: not available; no classifier score is emitted.

## Known limitations
Permission-vector labels are a weak proxy for maliciousness and may encode app-category/source bias. A future model requires leakage-resistant splits by family/source/time, benign coverage, threshold-specific false-positive/false-negative reporting, reproducible training and licence review.

## Release policy
Do not add an empty, placeholder, random-weight, or hand-crafted tensor file and call it trained. Runtime reports this layer disabled until a real model and evaluation report are reviewed.
