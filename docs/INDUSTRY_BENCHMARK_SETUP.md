# Phase F — Cloud Industry Benchmark setup

This workflow runs inside the existing SafeMobile repository. It does not require the owner's computer or another repository.

## One-time malware dataset approval

The official [F-Droid index](https://f-droid.org/en/docs/All_our_APIs/) supplies 1,000 benign-labelled APK candidates automatically. F-Droid origin is a proxy label, not independent assurance of cleanliness.

The University of New Brunswick publishes the [CICMalDroid 2020 dataset](https://www.unb.ca/cic/datasets/maldroid-2020.html), but no license-cleared, stable, SHA-256-pinned manifest of 1,000 directly downloadable APKs is currently supplied by SafeMobile. The workflow will not silently use an unknown mirror or fabricate results.

A researcher or authorized data administrator must provide a public HTTPS manifest with exactly 1,000 licensed malware APK URLs and their verified SHA-256 values. Example format (not a real dataset):

~~~json
{
  "schema_version": 1,
  "name": "Owner-approved malware subset",
  "revision": "exact-revision",
  "license": "approved research terms",
  "source": "https://www.unb.ca/cic/datasets/maldroid-2020.html",
  "samples": [
    {
      "url": "https://approved-research-host.example/sample0001.apk",
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
~~~

The example links and checksum are placeholders. The actual manifest must list exactly 1,000 real, distinct, licensed APKs; no APKs belong in Git history. Obtain an independent SHA-256 digest of the complete JSON manifest.

In **GitHub repository Settings → Secrets and variables → Actions → Variables**, create:

- **INDUSTRY_MALWARE_MANIFEST_URL** — HTTPS URL of the approved JSON manifest.
- **INDUSTRY_MALWARE_MANIFEST_SHA256** — lowercase, 64-character SHA-256 digest of the complete JSON manifest.

## Trigger the benchmark

1. Open [the SafeMobile Actions tab](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions).
2. Select **Industry Benchmark (2,000 real APKs)** from the left sidebar.
3. Click **Run workflow**, select **main**, then confirm **Run workflow**.
4. Open the new workflow run. On success, download its **industry-benchmark-report** artifact. A separate publish job automatically commits **docs/BENCHMARK_REPORT.md** to main. Only aggregate report text is committed.

Without the two approved variables, missing samples, invalid hashes, or an incomplete device scan, the workflow **fails closed**. It will not report made-up detection percentages.

The temporary GitHub runner downloads only 25 APKs at a time, verifies APK hashes, pushes file bytes to an isolated Android emulator and runs the production **PackageScanner** through Android instrumented tests. The corpus APKs are **never installed or executed**. The real hash engine, limited DEX YARA matcher, and production-gated ML scanner are exercised. The untrained research model is disabled and therefore cannot be counted as a detector.

## Interpreting the result

Confirmed TPR equals 1,000-sample malicious THREAT verdicts divided by 1,000. Confirmed FPR equals 1,000-sample benign THREAT verdicts divided by 1,000. SUSPICIOUS signals are reported separately as triage. Average latency includes APK parsing, hashing, detection and local processing on the emulator. A NOT_SCANNED result means the benchmark is incomplete.

This is a single emulator and two dataset subsets, **not an independently certified industry-wide detection rate**. A meaningful external comparison would additionally require independent label audits, recent diverse APKs, physical-device measurements, reproducible performance baselines and uncertainty estimates.

The hidden Settings card is unlocked by tapping the app version text seven times. It reads the report embedded at **build time**, not a live GitHub URL. The already built v1.0.17 Play AAB will not show a newly generated report; a subsequent app build is required.
