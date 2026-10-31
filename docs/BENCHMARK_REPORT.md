# SafeMobile Industry Benchmark Report

**Status: NOT MEASURED (31 October 2026).** [Cloud benchmark run #1](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41171013990) **failed** during actual instrumented scanning: Android reported `EACCES (Permission denied)` when opening `/storage/emulated/0/Android/data/com.vibesync.antivirus.debug/files/industry-benchmark/batch.json`. The SHA-256 manifest and 200-sample plan were generated, but no verified complete 200-sample result was published. TPR, FPR and latency therefore remain unavailable.

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

These are **source-derived labels**, not independently adjudicated ground truth. The app now packages a trained, SHA-256-pinned 18,584-byte Drebin **215-feature research model**, but it is **NOT activated for production malware scoring** (`validated=false`, `production_ready=false`). Its historical 97.45% research holdout cannot be used as this benchmark's TPR. The bundled YARA layer is a limited DEX literal matcher, not full libyara.

See [INDUSTRY_BENCHMARK_SETUP.md](INDUSTRY_BENCHMARK_SETUP.md) and [BENCHMARK_EVALUATION.md](BENCHMARK_EVALUATION.md).
