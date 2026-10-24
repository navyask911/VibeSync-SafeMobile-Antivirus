# Third-party licences — Phase A and Security Posture

The following existing dependencies were inspected from `app/build.gradle.kts`; no Hypatia source, rules or dataset is copied or bundled in this change.

| Component | Purpose | License | Distribution note |
|---|---|---|---|
| Google Tink Android 1.16.0 | Keystore-wrapped encrypted local data | Apache License 2.0 | Existing dependency; preserve notice |
| Bouncy Castle bcprov-jdk18on 1.86 | Detached Ed25519 signature verification | MIT licence | Existing dependency; retain copyright/licence notice |
| AndroidX Room 2.7.2 | Indexed local hash database, migrations | Apache License 2.0 | Existing dependency |
| AndroidX WorkManager 2.10.2 | Local scheduled jobs | Apache License 2.0 | Existing dependency |
| Google Guava 33.4.8-android | Existing Bloom filter reader | Apache License 2.0 | Not enabled without a signed complete filter |
| TensorFlow Lite 2.17.0 | Existing optional dependency, no model | Apache License 2.0 | Capability DISABLED; dependency alone does not mean ML detection |
| Hypatia | **NOT INCLUDED** | GPLv3 | Source and databases may be subject to separate licences. No code or signatures copied; redistributing them requires independent compatibility and licence review |
| ClamAV databases | **NOT INCLUDED** | Database-specific redistribution terms apply | Parser interoperability is not a licence to ship external signature data |
| MH-100K / MH-1M | **NOT INCLUDED** | Dataset-specific terms require verification | Not present and not benchmarked |

This table is a focused Phase A review, not a substitute for the repository's dependency-graph/SBOM automation. Production packaging must retain the required licence texts and notices for the exact resolved dependency graph.
