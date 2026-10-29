# Third-party license inventory — detection-engine work

This file records detection-engine-specific license decisions. The CI-generated CycloneDX SBOM and THIRD_PARTY_NOTICES.md are the canonical inventories of resolved dependencies; any unresolved upstream metadata remains flagged for review.

| Component or data | License / status | Decision |
|---|---|---|
| Bouncy Castle bcprov-jdk18on 1.86 (already present before this phase) | Permissive Bouncy Castle license; exact upstream artifact notice must be retained | Used for Ed25519 verification; no new dependency was added in Phase A. |
| Google Tink tink-android 1.16.0 (existing) | Apache-2.0 | Existing Keystore-backed quarantine encryption remains unchanged. |
| VirusTotal YARA engine (libyara, not integrated) | BSD-3-Clause upstream | No JNI/native binaries are included. The bounded Kotlin matcher supports only a documented limited grammar and must not be described as libyara. |
| Takopii Android detection rules (adapted) | MIT, Copyright (c) 2026 Takopii Project Contributors | Five DEX-focused signatures adapted from banker-shape.yar, dcl-antiforensics.yar, rat-capabilities.yar and dropper.yar at upstream revision `2e539dc150228a06cc983c33367b06d605c12a85`. Source: https://github.com/F2u0a0d3/takopii . APK ZIP-header conditions removed and conditions narrowed for extracted DEX and supported Boolean grammar. MIT text is retained in NOTICE. These are generic heuristics, not validated malware family identifications. |
| Hypatia source code | AGPL-3.0-or-later | No code or rule set copied; the app is licensed Apache-2.0 and no AGPL-compatibility decision was made. |
| Mendeley 200K malware-hash research dataset, version 1 | CC BY 4.0 | Its citation and attribution are recorded in docs/THREAT_DATASET_ATTRIBUTION.md. It is not imported into the production database. |
| APKiD (considered for packer detection) | Dual-license GPL/commercial; no commercial license obtained | Not integrated and no source/rules copied. A bounded in-app filename/DEX-structure heuristic is used instead and is not represented as equivalent to APKiD. |\
| Runtime production hash definitions | Not bundled | Disabled until the owner/release process verifies redistribution rights, provenance, false positives, and signs the exact bytes with the configured trust root. |

Before adding a dependency or dataset, review the exact distributed artifact's license and upstream source. An SBOM license field alone is not legal approval. No Hypatia/AGPL source code or data is copied.

### DM Sans (Regular, Medium, Bold; bundled font assets)

- Upstream: https://github.com/googlefonts/dm-fonts (pinned revision `4412393b7d2de9fe7a92064c2dce9b5af5d7fd26`)
- License: SIL Open Font License 1.1, full license in `docs/licenses/DM_SANS_OFL.txt`
- Copyright 2014 The DM Sans Project Authors. Original unmodified static fonts; used only for Latin UI typography, with Android font fallback for unsupported scripts.

### Weekly ML research candidate distribution (v1.0.16)

- **OkHttp 4.12.0** by Square, Apache License 2.0, https://github.com/square/okhttp/tree/parent-4.12.0 (review canonical upstream LICENSE); download-only HTTP client, pinned, no inference traffic.
- **Drebin 215 research model bundle**: source https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/releases, training code under MIT; dataset attribution under CC BY 4.0 is in its DATASET_NOTICE.md. Source, model SHA-256 and schema are compared with the same release's checksums. Research release is not production-approved and downloaded candidates are never used as a malware detector.
- No dynamic code loading. The bundled untrained fixture, local YARA/hashes, and existing offline model validation remain untouched.
