# SafeMobile Industry Benchmark Report

**Status: NOT MEASURED.** No SHA-256-verified run of 100 MalwareBazaar-labeled Android malware candidates plus 100 F-Droid benign-labelled APKs has completed.

## Benchmark result

~~~json
{
  "status": "NOT_MEASURED",
  "timestamp_utc": null,
  "total_apps": 0,
  "malicious_apps": 0,
  "benign_apps": 0,
  "tpr_percent": null,
  "fpr_percent": null,
  "mean_latency_ms": null
}
~~~

Phase F now runs a 200-APK cloud pilot. The workflow generates an ephemeral 100-entry MalwareBazaar candidate SHA-256 manifest using the Actions secret, selects 100 pinned F-Droid APKs and performs read-only scanning in 10-file batches on an Android emulator. Sample APKs are never installed, executed, committed or uploaded as artifacts. Failed downloads, rate limits and incomplete scans fail closed.

These are **source-derived labels**, not independently adjudicated ground truth. The app's bundled model is currently an untrained 32-feature dummy and remains disabled. The separate research Drebin 215-feature model is not an activated production scanner, and 97.45% research holdout accuracy cannot be used as this benchmark's TPR. The bundled YARA layer is a limited DEX literal matcher, not full libyara.

See [INDUSTRY_BENCHMARK_SETUP.md](INDUSTRY_BENCHMARK_SETUP.md) and [BENCHMARK_EVALUATION.md](BENCHMARK_EVALUATION.md).
