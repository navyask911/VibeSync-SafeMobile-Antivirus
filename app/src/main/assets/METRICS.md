# Detection metrics

**Status:** NOT MEASURED — there is no legally verified, labeled APK malware test corpus and no >=1,000-sample benign APK corpus available as an approved local CI fixture. The checked-in research dataset is a hash manifest, not an APK binary corpus. CI must not invent effectiveness values from the EICAR test marker.

Last documentation review: 2026-10-24.
Code snapshot reviewed: `470f9de208b3c4a26e551921356ca3c75d96a2ff` (Phase C static-analysis head at the time this document was first prepared). This is a code-review reference, not a benchmark run.

| Metric | Value | Reason / interpretation |
|---|---|---|
| Malware true-positive rate (TPR / recall) | NOT MEASURED | No legally approved labeled APK malware test split and production signature database; no inference of efficacy from hash computation alone. |
| Benign false-positive rate (FPR) | NOT MEASURED | No approved corpus of at least 1,000 benign F-Droid APK binaries has been placed in CI; heuristics have not been evaluated against that corpus. |
| Precision | NOT MEASURED | No paired labeled malware/benign end-to-end corpus run. |
| Per-sample latency | NOT MEASURED | The Phase F harness and reference emulator run have not completed. |
| Peak RSS / additional ML memory | NOT MEASURED | No full-corpus run and no ML model is shipped. |
| TFLite accuracy / TPR / FPR / precision / recall | NOT MEASURED | ML engine is DISABLED; no validated model is loaded. |
| YARA TPR / FPR | NOT MEASURED | YARA engine and production rule set are DISABLED. |
| Signed hash database TPR / FPR | NOT MEASURED | Matcher implementation exists, but it is DISABLED until trusted signing configuration and a vetted production signature set are provisioned. |

## Benchmark provenance

- Malware research dataset identified in `docs/THREAT_DATASET_ATTRIBUTION.md`: Mendeley Data version 1, title “A 200K Malware Hash Dataset with Experimental Splits for Machine Learning Classification”, DOI `10.17632/xv84w8cc72.1`, publisher-declared CC BY 4.0. It is a manifest of hash records, not APK binaries; it is not treated as an operational threat feed or used to claim TPR.
- Benign APK corpus: NOT OBTAINED / NOT MEASURED. No APK binary corpus was bundled into Git or CI.
- Reference device/emulator: NOT MEASURED for the detection benchmark.
- Commit SHA/date for empirical metrics: NOT APPLICABLE UNTIL A BENCHMARK RUN COMPLETES. The snapshot SHA above does not attach any measured metric to itself.

## Regression-gate policy

Phase F will record JSON benchmark output. If legal sample corpora and a verified signature set are supplied to the offline harness, the measured values can be reported with dataset revision, corpus manifest hashes, device/emulator spec, and exact commit SHA. On the first real run, a baseline will be established; regression gates activate after the baseline exists. With missing corpora, metrics remain explicitly NOT MEASURED and no numbers or fake baseline will be emitted.