# SafeMobile Annual Security Benchmark Results

**For the latest product information and development updates, visit https://vibesyncro.com/safemobile.html.**

**For live metrics and model details, see the Live Threat Intelligence Dashboard:** [Link](https://navyask911.github.io/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/). The live research dashboard is separate from the independently verified annual APK-scanning ledger below.

This permanent historical ledger records SafeMobile's year-by-year **measured** Android threat-detection benchmark results. Entries must retain their execution date, immutable source provenance, sample counts, actual device scan results and GitHub Actions run identifier. An attempted run is not a measured result.

For current scan status and the app's Settings-screen summary, see the [active Benchmark Report](BENCHMARK_REPORT.md). For the test design, see [Industry Benchmark Setup](INDUSTRY_BENCHMARK_SETUP.md).

## Annual results ledger

| Year & Benchmark ID | Execution Date | Corpus Size | Corpus Source | True Positive Rate (TPR) | False Positive Rate (FPR) | Average Scan Latency | Shard Matrix Health |
|---|---|---|---|---|---|---|---|
| **2026 Baseline · [Industry Benchmark #11](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41224653496)** | **31 Oct 2026, 18:32:34 UTC** | **200 scanned**: 100 benign + 100 malicious-source APKs | **Malware:** pinned 500-SHA-256 text manifest, `MalwareSamples/Android-Malware-Samples` commit `cf802c63`; 100 byte-validated malicious-source APKs. **Benign:** F-Droid | **0.0%** | **0.0%** | **4,109.48 ms / APK** | **10/10 passed**; 200/200 scanned; 0 NOT_SCANNED |

**2026 baseline status: MEASURED.** [Benchmark #11](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41224653496) passed all 10 emulator shards and the aggregator verified 100 malicious-source and 100 benign APK scans with `not_scanned=0`. Confirmed-threat **TPR was 0.0%**, meaning **zero of the 100 source-labeled malicious APKs received a confirmed THREAT verdict**; confirmed-threat FPR was **0.0%**. The **advisory** `SUSPICIOUS` triage rates were **12.0% TPR** and **8.0% FPR**, and are not confirmed malware detection. **Mean latency was 4,109.48 ms per APK.** The separate Drebin 97.45% research holdout is not this benchmark's TPR; `research_ml_samples_scored=0` in this run. Source labels are not independently adjudicated ground truth.

## Zero-Binary Repository methodology

1. **Text-only corpus index.** The Git tree contains only the 500 SHA-256 filenames and benchmark scripts, never malware `.apk` or `.zip` binaries. The manifest is sourced from an immutable upstream Git commit (`cf802c63baf8d435e8d4e663a24187056be3918a`); source-provided malware labels are **not** independently adjudicated ground truth.
2. **Ephemeral acquisition.** GitHub Actions runners download candidate files directly into their private temporary scratch space (`$RUNNER_TEMP/industry`, typically under `/tmp/` or equivalent). Binary files never enter the source checkout, commits, releases or uploaded benchmark artifacts. Each matrix job independently downloads only its SHA-256-pinned assignments; runner files are not shared across jobs.
3. **Strict APK validation.** Enforce `PK\\x03\\x04` ZIP magic, a ZIP-readable `AndroidManifest.xml` with compiled Android binary XML, bounded decompression and exact SHA-256 matching. If a candidate is wrapped in an encrypted ZIP, attempt `pyzipper` decryption with password `infected` inside the isolated runner. Exclude malformed, corrupt, missing or non-APK files.
4. **Exactly 200 read-only scans.** Preflight stops at exactly **100 verified malicious APKs**; combine them with **100 distinct F-Droid benign APKs**. Run 10 disjoint emulator shards (10 malicious + 10 benign each). APK samples are inspected by the actual SafeMobile scanner without installing or executing the candidate apps.
5. **Fail-closed aggregation and cleanup.** Only publish TPR, FPR and mean latency when **all 10 shards** supply valid on-device results for **200/200 APKs**, with **zero `NOT_SCANNED`** outcomes. If preflight, downloads, scanning or aggregation fail, record the attempt as **NOT MEASURED**. Delete all temporary malware binaries on success or failure; upload only hash-based manifests and nonbinary aggregate results.

## Annual reporting rules

- **Cadence:** Preserve a separate baseline record for each calendar year; do not overwrite a previously completed annual entry with a later run.
- **Evidence:** Record the execution date, run URL/ID, source commit, class sizes, shard completion, measured TPR, FPR and mean scan latency from the verified aggregator output.
- **Pending or failed runs:** Use **PENDING** or **NOT MEASURED** as appropriate; never guess, extrapolate, use fixture results or substitute research-model holdout accuracy.
- **Scope:** These figures characterize the specific APK corpus, SafeMobile build, emulator configuration and test date, not a guarantee of universal malware detection or independent certification.
- **2026 verified baseline:** Recorded from the successful Benchmark #11 aggregator. Keep its measurements immutable as a historical snapshot; corrections require a linked reproducible run and an explicit note, not silent replacement.

## Supporting references

[Current Benchmark Report](BENCHMARK_REPORT.md) · [Industry Benchmark Setup](INDUSTRY_BENCHMARK_SETUP.md) · [Benchmark Evaluation](BENCHMARK_EVALUATION.md) · [Benchmark #11 execution](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41224653496)
