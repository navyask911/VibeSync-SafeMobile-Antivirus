# Measured security metrics

**Phase A status (2026-10-25): NOT MEASURED — validated, licensed malware and benign APK corpora were not supplied to CI.** Do not interpret a passing unit test as a detection-accuracy measurement.

| Metric | Value | Why |
|---|---|---|
| True-positive rate (TPR) | **NOT MEASURED** | MH-100K licensed test split unavailable |
| False-positive rate (FPR) | **NOT MEASURED** | 1,000 reproducibly sampled and licensed F-Droid APKs unavailable |
| Precision / recall | **NOT MEASURED** | Requires the above labelled corpora |
| Scanning RSS (<120 MB target) | **NOT MEASURED** | Physical-device benchmark/profiled corpus required |
| Total scan latency (<500 ms target) | **NOT MEASURED** | Controlled APK set and hardware required |
| TFLite latency / memory | **DISABLED** | No trained, independently validated TFLite artifact |
| YARA runtime / detection | **DISABLED** | No validated JNI engine or licensed rules |
| Bloom pre-screen | **DISABLED** | No signed, source-complete verified Bloom snapshot |
| Hash algorithms | MD5, SHA-1, SHA-256 | Supported by streaming HashCalculator and exact Room lookups |
| Detached Ed25519 checks | Unit tests | No production public key configured; absent key disables external signed bundle acceptance |

No efficacy percentage, zero-error claim, or third-party certification is inferred from implementation tests. A future benchmark must publish corpus provenance, sample counts, immutable dataset revisions, split definitions, hardware, CI artifact paths, measurements, and signed expected baselines before threshold gates are switched on. The *first* reproducible benchmark is a baseline, not a regression failure. Until then: **NOT MEASURED**.

Unit tests cover accept/reject paths for signed manifests, tampered payloads, unsigned input, incorrect algorithm formats and bounded archive reads. They do **not** constitute a fuzzing certification. Zip-bomb and malformed-archive full fuzzing: **NOT MEASURED — no dedicated fuzz campaign was run**.
