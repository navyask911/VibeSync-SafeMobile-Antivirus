# SafeMobile Detection Coverage Matrix

**Reviewed:** 22 October 2026  
**Purpose:** state what is shipped and wired into ordinary scan flows, not measure detection efficacy.

| Layer | Current state | Evidence/behavior | Release limitation |
|---|---|---|---|
| Local hash matching | **Active — extremely limited** | Ordinary scan path calculates SHA-256 and looks up its protected value in local Room definitions/allowlist. The bundled offline definitions contain only the harmless EICAR test-marker signature. | Does not constitute a real malware signature set. A clean/no-match result is not proof of safety. |
| SHA-256/SHA-1/MD5 calculation | **Active** | One-pass streaming hash calculator used for readable APKs/files. | Hash computation itself is not malware detection. Comprehensive SHA-1/MD5 indexes are not shipped. |
| Permission/manifest heuristics | **Active heuristic** | PackageScanner reviews available requested permissions, accessibility service metadata, debug-certificate signals and compound risk. | Triage only. False positives/negatives expected; no classifier score from a validated trained model. |
| Root/Magisk/Xposed/LSPosed/device integrity | **Active heuristic** | Injectable offline probes check common root/hook paths, manager package visibility, build properties, SELinux enforcement file, debugger state and emulator-like build properties. A bounded multiplier influences permission-risk score. | Can be hidden/spoofed; package visibility, filesystem and hidden system-property access are platform-limited. Not cryptographic attestation or proof of a clean OS. |
| Bloom hash index | **Disabled in ordinary scan flow** | A loader checks manifest filename/version/entry count and SHA-256 before deserializing a Guava Bloom filter; missing/invalid assets fail closed. | No valid non-empty `assets/hypatia_bloom.db` and matching `manifest.json` is shipped, and PackageScanner does not currently query this loader. No Bloom detections are claimed. |
| YARA DEX/asset scan | **Disabled** | A stub/API explicitly reports `DISABLED` or unreadable-input state. | No libyara JNI runtime, supported-ABI `.so` files, curated rules or timeout-bounded native scan is present. |
| TFLite classifier | **Disabled / heuristic fallback** | An optional scorer attempts to load `permission_risk.tflite`; missing assets return `null` and the code documents heuristic fallback. No validated model asset is bundled; the scorer is not used by PackageScanner's current verdict path. | No model training provenance, evaluation, calibrated threshold or false-positive report. No ML classification is claimed. |
| Offline signer attestation | **Helper exists, not activated** | Offline helper can hash reported signing certificates and compare to an externally trusted expected fingerprint. | No independently pinned release signer is configured or enforced by ordinary scans. A certificate compared with a fingerprint supplied by itself is not trusted pinning. |
| Signed threat feed | **Verifier implemented; production source not configured** | The feed worker verifies detached Ed25519 manifest signature, source hash, strictly newer version and streamed payload SHA-256 before staged indicators are promoted. Room stores monotonic feed state; user opt-in is off on clean install. | Requires the build-time public key and a feed publisher that emits the agreed signed headers. No production public key or signed redistributable snapshot is bundled; sync fails closed without the key. |
| Install-source review | **Best effort** | Uses Android package installer metadata when available. | Cannot intercept installation before Android completes it; unknown sources may remain unknown. |
| Quarantine | **Implemented with constraints** | Tink Streaming AEAD, Android Keystore-wrapped keyset, hash/length verification and user-chosen restore destination. | Room isn't SQLCipher-encrypted; older quarantine items can be unencrypted. Physical-device restore, revocation and recovery tests remain required. |

## Required before upgrading a layer to “active”

- **Hash database:** curated open/free feed whose current terms permit the app's actual use and redistribution; reproducible generator; SHA-256/SHA-1/MD5 index or a clearly documented subset; signed/versioned manifest; reproducibility report; known-good and known-bad tests.
- **Bloom:** real entries, correct index construction, source/licence provenance, manifest digest, positive entry count, known-good/known-bad tests, and integration into the scanner's actual verdict path. A colocated hash manifest protects against accidental corruption but is not an independent signature trust root.
- **YARA:** tested native libyara for every distributed ABI, licence-reviewed rules, bounded CPU/memory/time, benign and safe test fixtures, and negative/positive regression coverage.
- **ML:** reproducible training/evaluation data, licensed asset, model card, held-out family/time evaluation, calibrated threshold, and false-positive/false-negative metrics. Do not create a placeholder or random-weight model.
- **Attestation:** independent trusted signer fingerprint pin, update/rotation policy, and test showing a mismatched signer fails the intended gate.

## Gate decision

**Phase 1 source hardening is not a production detection release.** The runtime coverage registry, README and this matrix intentionally say which layers are disabled or not wired into scanning. Do not make comprehensive AV or tested detection-rate claims until the above gates pass.
