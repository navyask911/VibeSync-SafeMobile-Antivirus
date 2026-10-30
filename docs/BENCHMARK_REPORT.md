# SafeMobile Industry Benchmark Report

**Status: NOT MEASURED.** The 2,000-APK, owner-approved, provenance-pinned benchmark has not completed yet. Do not treat CI unit tests as malware detection metrics.

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

The manually triggered workflow downloads 1,000 distinct F-Droid APKs and 1,000 SHA-256-pinned, licensed malware APKs into temporary GitHub runner storage, scans archive bytes in a cloud Android emulator, and uploads results without committing APKs. The malware manifest must first be provided and approved. The current dummy/untrained ML model must not count as a detector. YARA uses a bounded DEX literal matcher; no claim of full libyara support. A reference emulator is not a substitute for testing representative physical devices.

See [BENCHMARK_EVALUATION.md](BENCHMARK_EVALUATION.md).
