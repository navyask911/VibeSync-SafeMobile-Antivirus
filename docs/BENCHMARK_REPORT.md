# SafeMobile Industry Benchmark Report

**Annual historical results:** [ANNUAL_BENCHMARK_RESULTS.md](ANNUAL_BENCHMARK_RESULTS.md). The active report covers only verified current results; the annual ledger keeps the year-by-year record.

**Status: NOT MEASURED (31 October 2026).** [Cloud benchmark run #1](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41171013990) **failed** during actual instrumented scanning: Android reported `EACCES (Permission denied)` when opening `/storage/emulated/0/Android/data/com.vibesync.antivirus.debug/files/industry-benchmark/batch.json`. The SHA-256 manifest and 200-sample plan were generated, but no verified complete 200-sample result was published. TPR, FPR and latency therefore remain unavailable.

**2026 annual baseline: PENDING — Benchmark #11 in progress.** [Manually dispatched run #11](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41224653496). Do not enter TPR, FPR or latency before the complete, independently verified 200-APK aggregate is available and confirmed by the owner.

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

The 200-APK pilot uses 100 source-labeled malicious Android APKs and 100 F-Droid APKs, split across 10 emulator shards (10 malicious + 10 benign each). Malware candidate filenames come from a text-only 500-SHA-256 manifest pinned to upstream commit `cf802c63`. APK binaries are downloaded and strictly validated only in temporary GitHub Actions runner storage, then deleted. The scanner inspects the files read-only; sample APKs are never installed, executed, committed to Git or uploaded as artifacts. Incomplete scans and insufficient valid samples fail closed.

These are **source-derived labels**, not independently adjudicated ground truth. The app now packages a trained, SHA-256-pinned 18,584-byte Drebin **215-feature research model**, but it is **NOT activated for production malware scoring** (`validated=false`, `production_ready=false`). Its historical 97.45% research holdout cannot be used as this benchmark's TPR. The bundled YARA layer is a limited DEX literal matcher, not full libyara.

See [INDUSTRY_BENCHMARK_SETUP.md](INDUSTRY_BENCHMARK_SETUP.md) and [BENCHMARK_EVALUATION.md](BENCHMARK_EVALUATION.md).
