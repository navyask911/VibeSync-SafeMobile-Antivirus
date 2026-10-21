# SafeMobile security model

**Review date:** 22 October 2026  
**Release posture:** development candidate; detection efficacy and some release controls remain unverified.  
**Builds:** `offline` is the recommended distribution variant; `feed` is a separate network-enabled variant.

## Security objectives

1. Keep ordinary scan processing local and usable without a network connection.
2. Prevent accidental Internet permission from appearing in the recommended offline artifact.
3. Avoid ad, analytics, telemetry and crash-reporting SDKs in release artifacts.
4. Keep new quarantine payloads encrypted and verify hashes before reporting success/restore.
5. Make missing detection capabilities visible rather than returning fabricated scan success.
6. Keep optional feed acquisition separate from scanning, explicitly consented, HTTPS-only and authenticated by a detached Ed25519 signature and monotonic version.

## In-scope threats

- Sideloaded or repackaged apps that are readable to the ordinary Android package manager and whose APK hashes/metadata can be inspected.
- Known hash matches present in local definitions or a user-configured, correctly signed feed.
- Some stalkerware-like permission combinations and accessibility-service declarations that warrant user review.
- Tampering with a downloaded feed manifest/body, unsigned feed responses, replay of old accepted feed versions, and accidental cross-source feed reuse.
- Opportunistic access to quarantined content, where new items are encrypted with Tink Streaming AEAD and an Android Keystore-wrapped keyset.
- Accidental addition of common ad/analytics/crash SDKs or Internet permission to the offline release artifact, to the extent covered by the CI bytecode/manifest marker checks.
- Accidental cloud/device backup configuration, to the extent covered by manifest and XML rule checks.

## Out-of-scope / not guaranteed

- Zero-day malware, unknown families not represented by signatures, obfuscated code that does not trigger heuristics, kernel exploits, system-partition malware, compromised firmware/boot chain, or a rooted device hiding its state.
- Physical access by a privileged attacker, forensic extraction by a compromised OS/OEM backup path, runtime memory inspection by a privileged process, malicious accessibility/overlay behavior that the app cannot observe, or a malicious trusted feed publisher.
- Blocking a package install before Android installs it, silently uninstalling apps, universal scanning of inaccessible private app data, or protection against every browser/link/phishing threat.
- A “clean” result as proof of safety. The current bundled operational signature baseline is only EICAR test marker content.

## Data-flow diagram

```mermaid
flowchart TD
    A[Installed package metadata / user-selected file] --> B[Local hash and permission checks]
    B --> C[Local Room definitions and imported indicators]
    C --> D[Local verdict and audit history]
    D --> E[App-private storage]
    D --> F[Optional encrypted quarantine]
    F --> G[Tink Streaming AEAD]
    G --> H[Android Keystore-wrapped per-install keyset]

    subgraph Offline build — no INTERNET permission
      A
      B
      C
      D
      E
      F
      G
      H
    end

    I[User saves HTTPS feed URL and opts in] --> J[Feed flavor worker]
    J --> K[HTTPS feed endpoint]
    K --> L[Detached Ed25519 signature check]
    L --> M[Source + monotonic version + body SHA-256 checks]
    M --> N[Bounded parser / staging Room table]
    N --> O[Atomic local indicator promotion]
    O --> C

    D -. no outgoing scan-data path .-> X[No scan upload / telemetry / analytics]
```

The offline flavor contains no Internet permission in its merged manifest. The separate feed flavor adds that permission only for optional feed synchronization. This diagram describes intended code paths; it is not a packet-capture result. A debug socket-attempt monitor and network-instrumentation proof are still open QA gates.

## Data inventory and storage

| Data | Where / how used | Egress behavior |
|---|---|---|
| APK/file bytes | Read in streaming/local code for hashing; not intentionally retained as scan input | No scan-data upload path |
| SHA-256/SHA-1/MD5 | In-memory calculation; hashes may be stored protected in scan audit/definition records | No intentional upload |
| Local threat definitions | Room; encrypted hash/metadata storage exists for part of the signature path; imported feed indicators are local | No cloud dependency for scanning |
| Scan history | App-private Room rows with label/package-or-path, time, verdict, duration, session and threat event ID | Not intentionally uploaded; Room as a whole is not SQLCipher-encrypted |
| Quarantine files | App-private no-backup directory; new payloads use Tink Streaming AEAD and integrity verification | No upload |
| Quarantine metadata and preferences | App-private Room/shared preferences | Not intentionally uploaded; filenames/labels may identify user activity |
| Feed endpoint/auth key (feed variant only) | Endpoint stored in app-private config; optional Auth-Key is protected locally using app's existing Keystore encryption path | A consented feed request contacts the selected endpoint; endpoint/auth credential may be sent to that provider |
| Ed25519 public key | Build configuration / BuildConfig | Public trust root; private signing key must remain outside app/repository |
| Audit/event UUIDs | Locally generated and stored for local correlation | No external registration service |

**Important:** the Room database is not SQLCipher-encrypted and some rows include package/file labels and audit metadata. The project must not claim it stores “only non-sensitive hashes” until fields are minimized/retention-limited or database encryption is added and tested.

## Cryptographic inventory

| Primitive / key | Purpose | Storage and rotation |
|---|---|---|
| SHA-256, SHA-1, MD5 | Non-secret hashes of readable files/indicators. SHA-256 is used for feed payload binding and source key; weaker hashes are for compatibility/indexing only. | Computed locally. No rotation; do not use MD5/SHA-1 for trust decisions. |
| Ed25519 public key | Verify detached signature of a feed manifest in the `feed` flavor. | Supplied as build-time Base64 public key. Public key is not secret but is security-critical. Change it via reviewed release and publisher-key rotation policy. No production key is configured in this candidate. |
| Ed25519 private signing key | Signs the manifest at the feed publisher. | Must be stored outside the repo and app in an access-controlled signing system; rotation/revocation procedure is not yet operational. Never distribute it with the app. |
| Tink Streaming AEAD keyset | Encrypt/ authenticate quarantined file payloads. | Per-install keyset stored in app-private no-backup storage and wrapped by Android Keystore. If Keystore/keyset is lost or invalidated, content may be unrecoverable; key rotation and legacy-item migration remain operational risks. |
| Android Keystore AES-GCM key for feed Auth-Key | Protects optional provider credentials at rest where the existing feed config store uses this path. | Key is device-local and not exported in app storage. Keystore reset/uninstall can make saved encrypted configuration unreadable. |

No SQLCipher database key is present. The OS backup settings are configured to exclude app data, but device-specific backup/restore behavior has not been empirically verified.

## Release controls and open gates

- [x] Offline manifest excludes `INTERNET`; only the `feed` flavor adds it.
- [x] Ads/UMP/Play In-App Updates dependencies and calls removed from the Android app.
- [x] Manifest declares backup disabled; extraction rules exclude app domains.
- [x] Local root/hook/build-property/SELinux/debugger/emulator heuristics are integrated as best-effort triage signals.
- [x] Quarantine payloads are encrypted and hash/length checked.
- [x] Feed verifier supports detached Ed25519 signatures, body digest binding, source binding and strict monotonic versions.
- [ ] Configure the production feed public key and licensed signed feed snapshot; exercise with publisher-owned integration tests.
- [ ] Ship a reproducible, licensed hash database, native YARA runtime/rules, and a trained/evaluated TFLite model or leave each layer disabled (they currently remain disabled).
- [ ] Activate signer pinning with an independent expected release certificate and enforce it in the scan/release path.
- [ ] Encrypt Room or minimize identifying stored data, add retention controls and verify privacy promises.
- [ ] Add a debug socket-attempt monitor/network test and independently verify offline builds do not attempt sockets during scans.
- [ ] Verify no backup extraction on representative devices, test quarantine round-trip, large-feed/redirect/outage paths, and complete emulator matrix.
- [ ] Finish SBOM/licence metadata review, Play Console permission declaration and native-speaker localization review.

See [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md), [PLAY_PERMISSIONS.md](PLAY_PERMISSIONS.md), [LOCALIZATION_REVIEW.md](LOCALIZATION_REVIEW.md), and [RELEASE_GATES.md](RELEASE_GATES.md).
