# Detection metrics

**Status:** NOT MEASURED — no owner-approved malware APK holdout corpus, no >=1,000-sample approved benign APK corpus, and no device-generated scan outcome report are supplied to CI. The repository's cited research dataset is a hash manifest, not an APK binary corpus.

Last documentation review: 2026-10-25.
Benchmark implementation: `scripts/benchmark_detection.py`; unit tests: `scripts/test_benchmark_detection.py`.

| Metric | Value | Reason / interpretation |
|---|---|---|
| Malware true-positive rate (TPR / recall) | NOT MEASURED | Requires labeled malicious APKs, a fully verified corpus manifest and actual on-device scan outcomes. `THREAT` is a confirmed match; `SUSPICIOUS` is separate triage. |
| Benign false-positive rate (FPR) | NOT MEASURED | Requires at least 1,000 approved benign APK binaries and actual on-device scan outcomes. |
| Triage TPR / FPR | NOT MEASURED | Requires the same paired malicious/benign result corpus; `THREAT` or `SUSPICIOUS` counts as triage. |
| Confirmed precision / triage precision | NOT MEASURED | Requires both malicious and benign ground-truth samples and actual results. |
| `NOT_SCANNED` rate | NOT MEASURED | Unscanned files count separately and a `NOT_SCANNED` malware sample is not counted as a true positive. |
| Mean / P50 / P95 latency | NOT MEASURED | The report must include wall-clock scan duration in milliseconds from the device run. |
| P95 peak-memory delta | NOT MEASURED | Each sample must include measured incremental peak memory in KiB; otherwise this individual metric remains NOT MEASURED. |
| TFLite accuracy / TPR / FPR / precision / recall | NOT MEASURED | ML is DISABLED; no trained and validated model is shipped. |
| YARA TPR / FPR | NOT MEASURED | YARA runtime and production rule set are DISABLED. |
| Signed hash database TPR / FPR | NOT MEASURED | Engine remains DISABLED until the owner supplies an approved signing trust root and vetted signature database. |

## CI behavior

Every CI run executes `python3 -m unittest discover -s scripts -p 'test_*.py' -v` and writes `build/detection-benchmark.json`. Since CI currently has no legally approved APK corpus or device-generated outcomes, that artifact is expected to say `NOT_MEASURED` and every efficacy metric must remain the literal string `NOT MEASURED`. It is not a measurement run and does not create a baseline.

## Input and provenance format

The benchmark evaluator consumes an outcome JSON file created by a real, separately executed Android scan run. The top-level report must use `schema_version: 1`, a `dataset` object, and a non-empty `samples` array. Dataset metadata fields are `name`, `revision`, `license`, `source`, `manifest_sha256`, `corpus_sha256`, `reference_device`, `platform_version`, and `commit_sha`. Each sample has a unique anonymized `sample_id`, ground-truth `label` (`malicious` or `benign`), actual scanner `verdict` (`THREAT`, `SUSPICIOUS`, `NO_MATCH`, or `NOT_SCANNED`), numeric measured `duration_ms`, and optionally measured `peak_memory_delta_kb`.

Supply a separately reviewed JSON dataset manifest with `schema_version: 1` and the same `name`, `revision`, `license`, and `source`. Supply a corpus manifest with `schema_version: 1` and `samples`, each containing `sample_id`, `label`, safe relative `relative_path`, and the APK's SHA-256 hex digest. The evaluator checks the manifests' exact SHA-256 digests, every APK file hash, labels/sample IDs, ZIP/path-boundary safety, and equality with an owner-approved dataset-manifest hash allowlist.

Metrics are only marked `MEASURED` when the manifest hash equals the owner-approved value passed in `--approved-dataset-manifest-sha256` or provided by the protected `SAFE_MOBILE_APPROVED_DATASET_MANIFEST_SHA256` environment variable, manifest digests match the result report, all APK file hashes match, sample IDs and labels exactly match, at least one malicious sample exists, and the benign count meets `--min-benign` (default 1,000). Without the approval allowlist or any required files, the result remains `NOT_MEASURED`; no guessed or self-asserted corpus is accepted as approved.

Example invocation once an approved local corpus and a real device-run result exist:

```sh
python3 scripts/benchmark_detection.py \
  --input build/on-device-outcomes.json \
  --dataset-manifest /secure-corpus/dataset-manifest.json \
  --corpus-manifest /secure-corpus/apk-corpus.json \
  --sample-root /secure-corpus/apks \
  --approved-dataset-manifest-sha256 "$SAFE_MOBILE_APPROVED_DATASET_MANIFEST_SHA256" \
  --output build/detection-benchmark.json
```

The tool validates reported observations; **it does not run the Android scanner or generate scan outcomes**. Those outcomes must come from a separately executed instrumented/device run and be retained with the exact app commit, device/OS, and corpus digest. Do not check malware APK binaries or secrets into the repository.

## Regression gate

A baseline can only be created from an approved, fully measured report after a manual benchmark review; no baseline is included today. Once a comparable measured baseline exists, pass it using `--baseline`. The evaluator refuses to compare reports unless both are `MEASURED` and dataset revision, dataset manifest hash, corpus hash, reference device, and platform version match. Defaults fail the gate when benign FPR rises by more than 0.005 absolute (0.5 percentage points) or P95 latency rises by more than 20%; the tolerances are configurable via CLI flags. A missing or non-comparable baseline remains `NOT_RUN`/fails closed rather than receiving fabricated values.

## Dataset and model context

- The Mendeley Data v1 entry cited in `docs/THREAT_DATASET_ATTRIBUTION.md` is a research hash manifest (publisher-declared CC BY 4.0), not a corpus of APK binaries or an operational threat feed. It is not used to claim TPR/FPR.
- Benign APK corpus and device benchmark: NOT OBTAINED / NOT MEASURED.
- Commit-specific empirical metrics: NOT AVAILABLE. A source commit SHA is not evidence of a benchmark run.