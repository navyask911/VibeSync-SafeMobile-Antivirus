# SafeMobile Industry Benchmark Report

Read-only Android emulator APK scans (samples NEVER installed/executed). THREAT counts as a confirmed detection; SUSPICIOUS counts only for triage.

## Benchmark result

~~~json
{
  "benign_apps": 100,
  "fpr_percent": 0.0,
  "malicious_apps": 100,
  "mean_latency_ms": 268.83,
  "ml_samples_scored": 200,
  "not_scanned": 0,
  "plan_sha256": "835960edbe0f5450c2460bdcaadfd26685395dd536aabca3216180faa9709293",
  "provenance": {
    "byte_validated_malware_apks": 100,
    "commit": "9043bd102ffd9955df244d1f3f0ae7c5bc6d76a8",
    "fdroid_index_sha256": "aeb98175b400eafdb6dd9808256ab89404652effed88aebefbf72efaa1fa654f",
    "label_limitations": "GitHub malware corpus/F-Droid source labels are not independently validated ground truth",
    "malware_license": "Research-only, source-derived labels; binary redistribution prohibited",
    "malware_manifest_sha256": "011276dad07b604cc05b331a0f144209906c274d2eea924e2481ca0425303e37",
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
  "timestamp_utc": "2026-11-27T19:08:50.618212+00:00",
  "total_apps": 200,
  "tpr_percent": 0.0,
  "triage_fpr_percent": 7.0,
  "triage_tpr_percent": 13.0,
  "yara_states": [
    "MATCHES",
    "NO_MATCH"
  ]
}
~~~

Research ML scores are independent of production threat verdicts; ML-only rates are shown only if all 200 samples were scored. Models/definitions not active in the scanned build cannot contribute to measured efficacy. Results apply only to this corpus, emulator and commit.
