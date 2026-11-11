# SafeMobile Industry Benchmark Report

**Final status: MEASURED — Benchmark #11 verified.** [2026 Annual Benchmark Results](ANNUAL_BENCHMARK_RESULTS.md) · [Successful 10-shard execution](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41224653496).

Read-only Android emulator APK scans (samples NEVER installed/executed). THREAT counts as a confirmed detection; SUSPICIOUS counts only for triage.

## Benchmark result

~~~json
{
  "benign_apps": 100,
  "fpr_percent": 0.0,
  "malicious_apps": 100,
  "mean_latency_ms": 4109.48,
  "ml_samples_scored": 0,
  "not_scanned": 0,
  "plan_sha256": "c17d37ff4019e80ac6aa3ddf2a43a3f9e68c11f1c96e3ae2ce58dcbda3e0e4f0",
  "provenance": {
    "byte_validated_malware_apks": 100,
    "commit": "cab8b3e1cf1c490f3e299944240171e438f000d6",
    "fdroid_index_sha256": "125a809fc8ce055b87f68e53b4a1ea6cba8888bce70b40b382ee50c76a0bd105",
    "label_limitations": "GitHub malware corpus/F-Droid source labels are not independently validated ground truth",
    "malware_license": "Research-only, source-derived labels; binary redistribution prohibited",
    "malware_manifest_sha256": "4c72957364ad30afbe56bf7138deaff5dbfbbd6de751da00d6f8013f24669d49",
    "malware_name": "500 GitHub-hosted Android malware research candidates",
    "malware_revision": "Pinned source commit cf802c63baf8d435e8d4e663a24187056be3918a",
    "malware_source": "https://github.com/MalwareSamples/Android-Malware-Samples",
    "malware_source_commit": "cf802c63baf8d435e8d4e663a24187056be3918a",
    "rejected_malware_candidates": 0
  },
  "research_ml_fpr_percent": null,
  "research_ml_samples_scored": 0,
  "research_ml_threshold": 0.5,
  "research_ml_tpr_percent": null,
  "status": "MEASURED",
  "timestamp_utc": "2026-10-31T18:32:34.557824+00:00",
  "total_apps": 200,
  "tpr_percent": 0.0,
  "triage_fpr_percent": 8.0,
  "triage_tpr_percent": 12.0,
  "yara_states": [
    "MATCHES",
    "NO_MATCH"
  ]
}
~~~

Research ML scores are independent of production threat verdicts; ML-only rates are shown only if all 200 samples were scored. Models/definitions not active in the scanned build cannot contribute to measured efficacy. Results apply only to this corpus, emulator and commit.

## Verified 2026 baseline

| Measurement | Verified value |
|---|---:|
| Confirmed-detection TPR | **0.0%** |
| Confirmed-detection FPR | **0.0%** |
| Average scan latency | **4,109.48 ms per APK** |
| Corpus | **200/200 APKs**: 100 malicious-source + 100 benign |
| Emulator shards | **10/10 passed** |
| NOT_SCANNED | **0** |
| Advisory triage TPR / FPR | **12.0% / 8.0%** |
| Research ML samples scored | **0** |

**Interpretation:** Zero confirmed-detection TPR means no source-labeled malicious APK received a confirmed `THREAT` verdict in this run. Advisory triage is not confirmed detection, and the research-only ML model was not evaluated. This is a corpus-specific result, not independent certification or evidence of universal protection.

Historical results and annual methodology: [ANNUAL_BENCHMARK_RESULTS.md](ANNUAL_BENCHMARK_RESULTS.md).
