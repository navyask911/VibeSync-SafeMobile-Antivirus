# Detection benchmark evaluation — Phase F

This is a provenance-gated analysis tool, not an antivirus scan, and **does not measure efficacy in CI** until the owner supplies appropriately licensed APK malware and benign corpora, an approved manifest digest, and actual device-generated scan outcomes. The CI report at `build/detection-benchmark.json` intentionally remains `NOT_MEASURED`; no inference may be made from synthetic unit fixtures.

The executable is `scripts/benchmark_detection.py` and the unit tests are `scripts/test_benchmark_detection.py`. Offline test fixtures validate schema/provenance errors, sample hashes and labels, missing corpus, threshold gating, and FPR/latency regression behavior. A passing unit test is not a measured true-positive rate.

**Release controls:** Keep baseline comparison disabled until an owner-approved measured baseline with identical dataset revision, hashes, reference device, and OS platform exists. Do not check malware APK binaries, signing keys, PII, or API credentials into Git. Consult `docs/METRICS.md` for canonical measurement status and sources. The model and YARA runtimes remain disabled.
