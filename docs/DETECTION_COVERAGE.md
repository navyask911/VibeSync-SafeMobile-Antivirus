# SafeMobile Detection Coverage Matrix

**Status reviewed:** 2026-10-24. This is an implementation inventory, not an efficacy certification.

| Layer | State | Implemented behavior | Limitation / release decision |
|---|---|---|---|
| Legacy local SHA-256 signature matching | Active, severely limited | Room-backed signature matching and user/imported hashes. Bundled baseline contains only the harmless EICAR test marker. | Not a useful real-world malware set. Do not market as comprehensive antivirus. |
| Signed MD5/SHA-1/SHA-256 database engine | **DISABLED by default** | Signed ZIP bundle import, Ed25519 verification, monotonic versions, Bloom pre-filter and exact indexed Room lookups are implemented. | No independently vetted production database or trusted signing public key is bundled. Enable only after both are provisioned through a trusted release process. No real-world efficacy is claimed. |
| SHA-1/MD5 computation | Active | HashCalculator computes supported hashes in one streaming pass. | Hash computation alone is not detection; no comprehensive shipped database exists. |
| Permission/manifest heuristics | Heuristic | Risk-weighted permissions, accessibility declaration, install-source hints and combinations. | Can create false positives and miss malware; no ML model is called. |
| Deep static RiskReport | Advisory, enabled | Locally inspects exported component metadata, sensitive permission combinations, signer/debug metadata, DEX headers/entropy sample, common packer filenames, and a limited permission-to-DEX-string cross-check. Findings carry rule ID, severity, evidence and confidence. | Not a full manifest parser/disassembler; finding severity is heuristic. Reflection/native/dynamic loading can evade API references; file names/entropy and exported components can false-positive. Known-bad certificate fingerprints are DISABLED. |
| Root / hook / device integrity | Heuristic | Offline filesystem, package, build-property, SELinux, debugger and emulator indicators; multiplier informs package triage. | Best effort and bypassable; not attestation. |
| Legacy Hypatia Bloom asset | **Disabled** | Existing legacy loader validates a manifest and digest before deserializing. | Verified non-empty `assets/hypatia_bloom.db` is absent; no detections are claimed from that legacy asset. The new signed hash engine builds a Bloom pre-filter only after a signed database is validated. |
| YARA rules | **DISABLED** | API explicitly reports disabled/unreadable status; selected UTF-8 rule files can be stored as pending local files for review. | No Android libyara JNI runtime or curated, license-reviewed, signature-verified rules pack is shipped. Pending files are never compiled/executed. |
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
