# Third-party license inventory — detection-engine work

This file records detection-engine-specific license decisions. The CI-generated CycloneDX SBOM and THIRD_PARTY_NOTICES.md are the canonical inventories of resolved dependencies; any unresolved upstream metadata remains flagged for review.

| Component or data | License / status | Decision |
|---|---|---|
| Bouncy Castle bcprov-jdk18on 1.86 (already present before this phase) | Permissive Bouncy Castle license; exact upstream artifact notice must be retained | Used for Ed25519 verification; no new dependency was added in Phase A. |
| Google Tink tink-android 1.16.0 (existing) | Apache-2.0 | Existing Keystore-backed quarantine encryption remains unchanged. |
| VirusTotal YARA engine | BSD-3-Clause upstream | License-compatible in principle, but no vetted Android JNI build/native runtime or reviewed rules pack is bundled in this phase. YARA remains DISABLED. |
| Hypatia source code | AGPL-3.0-or-later | No code or rule set copied; the app is licensed Apache-2.0 and no AGPL-compatibility decision was made. |
| Mendeley 200K malware-hash research dataset, version 1 | CC BY 4.0 | Its citation and attribution are recorded in docs/THREAT_DATASET_ATTRIBUTION.md. It is not imported into the production database. |
| Runtime production hash definitions | Not bundled | Disabled until the owner/release process verifies redistribution rights, provenance, false positives, and signs the exact bytes with the configured trust root. |

Before adding a dependency or dataset, review the exact distributed artifact's license and upstream source. An SBOM license field alone is not legal approval. No Hypatia/AGPL source code or data is copied.