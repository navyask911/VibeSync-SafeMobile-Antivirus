# SafeMobile Detection Coverage Matrix

**Status reviewed:** 2026-10-22. This is an implementation inventory, not an efficacy certification.

| Layer | State | Implemented behavior | Limitation / release decision |
|---|---|---|---|
| Local SHA-256 signature matching | Active, severely limited | Room-backed signature matching and user/imported hashes. Bundled baseline contains only the harmless EICAR test marker. | Not a useful real-world malware set. Do not market as comprehensive antivirus. |
| SHA-1/MD5 computation | Active | HashCalculator computes supported hashes in one streaming pass. | Hash computation alone is not detection; no comprehensive shipped database exists. |
| Permission/manifest heuristics | Heuristic | Risk-weighted permissions, accessibility declaration, install-source hints and combinations. | Can create false positives and miss malware; no ML model is called. |
| Root / hook / device integrity | Heuristic | Offline filesystem, package, build-property, SELinux, debugger and emulator indicators; multiplier informs package triage. | Best effort and bypassable; not attestation. |
| Bloom filter database | **Disabled** | Loader validates manifest version/count and SHA-256 of `assets/hypatia_bloom.db` before deserializing. | Verified non-empty Bloom database/manifest is absent; no Bloom detections are claimed. |
| YARA DEX/assets | **Disabled** | API explicitly reports disabled/unreadable status. | No libyara JNI libraries or curated licensed rules are shipped. |
| TFLite classifier | **Disabled** | Status API returns no score when model is absent. | No validated `malware_model.tflite` exists; no synthetic model is shipped. |
| Offline signer attestation | **Disabled by default** | Helper compares signer/asset digest against external expected SHA-256. | No trusted signer fingerprint/database digest is configured. A manifest alone is not a trust root. |
| Signed feed manifest / rollback | **Not implemented** | Optional HTTPS JSON/CSV importer validates transport/records and stores imported indicators. | No detached Ed25519 verification or monotonic feed-version rollback gate exists. |
| Install-source review | Best effort | Uses Android package installer metadata where available. | Cannot block install before Android completes it; some sources report unknown. |
| Quarantine | Implemented with constraints | Tink Streaming AEAD, Android Keystore-wrapped keyset, hash/length verification and user-selected restore destination. | Physical-device QA remains required. |

## Required artifacts before activation

- `assets/hypatia_bloom.db` and versioned `assets/manifest.json`, trusted source/licence provenance and reproducible generation.
- `assets/yara_rules/` plus libyara JNI for supported ABIs, resource limits, compatible notices and benign/malicious regression fixtures.
- `assets/malware_model.tflite` only after reproducible training, evaluation, calibrated thresholds and false-positive/false-negative reports.

No empty, random, EICAR-relabelled, or synthetic content may be represented as a production threat set.

## Gate decision

**Phase 1 is not production-complete.** This change makes unavailable capabilities explicit, verifies any future Bloom asset before loading, and makes local integrity heuristics testable. It does not fabricate a threat dataset, trained classifier, YARA runtime, or trusted signer pin. Review this matrix before merging the Phase 1 PR.
