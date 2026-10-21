# VibeSync SafeMobile Antivirus

SafeMobile is a native Android security application built with Kotlin, Jetpack Compose Material 3, Room, WorkManager, Google Tink, and StateFlow-based MVVM.

**Release posture (reviewed 22 October 2026): development candidate, not a production-validated antivirus.** The local scanning path works on-device, but the bundled operational hash baseline is only the harmless EICAR test marker. A no-match result is not a claim that a file is safe. See the [Detection Coverage Matrix](docs/DETECTION_COVERAGE.md).

[Repository](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus) · [Issues](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues) · [Security model](docs/SECURITY_MODEL.md)

## Quick facts

| Item | Current implementation |
|---|---|
| Application ID | `com.vibesync.antivirus` |
| Android SDK | min 26 · compile 36 · target 36 |
| Candidate version | 1.0.3 · versionCode 20261023 |
| Recommended distribution build | `offlineRelease` |
| Cloud scanning / scan telemetry | None in the scanning path |
| Ads, analytics, crash-reporting SDKs | Removed from application variants |
| Default/offline manifest | No `INTERNET` permission |
| Optional feed manifest | `INTERNET` is added only by the `feed` flavor |
| Android data backup | Manifest disables backup and excludes data-extraction domains; an actual device backup test is still required |
| License | Apache License 2.0 for the project source, subject to separate third-party terms and any trademark rights |

**Do not call this “100% production grade” yet.** The detection feed/model/rules and real-world coverage, complete device QA, SBOM refresh and licensing review, Play Console permission review, and some privacy/QA verification gates remain open. A build passing CI does not close these gates.

## Network and privacy boundary

### Offline build (recommended for default distribution)

The base manifest and the `offline` flavor do not declare `android.permission.INTERNET`. The scanner calculates APK/file hashes, evaluates local permission/manifest heuristics, compares against local records, and records results in app-private storage. This build includes no Mobile Ads, UMP, analytics, telemetry, crash-reporting or Play In-App Updates SDKs. Core scan APIs do not use cloud scanning or reputation requests.

The application declares `android.permission.ACCESS_NETWORK_STATE` for local network-state awareness, but this is not permission to open Internet sockets. CI inspects the packaged offline manifest to catch an accidental Internet permission, and checks packaged bytecode for a list of known advertising, analytics, and crash SDK markers. These are useful checks, not a mathematical proof against every possible network call or third-party class.

### Optional feed build

The separate `feed` flavor adds Internet permission for an optional HTTPS threat-feed request. It must not make a request unless all of the following are true: a user configures the endpoint, the user confirms the in-app network-feed disclosure and opts in, and the build has a trusted Ed25519 public verification key. Feed responses require a detached signature that binds the source key, a strictly newer version and the payload SHA-256. Rollback state is stored locally in Room. Scan files, scan hashes, file contents and scan history are not intentionally included in feed requests.

**There is no configured production feed public key or signed public feed snapshot in this repository.** The worker therefore rejects remote feed sync until a trusted key has been supplied through the build environment. The private signing key must remain outside the source repository and app. The signed-feed protocol implementation is not equivalent to a real signed threat-data service.

## Detection coverage

| Layer | Status | What it does today |
|---|---|---|
| Local hash match | **Active, very limited** | Compares supported local records. The bundled baseline contains only the EICAR test-marker signature; no broad malware feed ships with the app. |
| SHA-256 / SHA-1 / MD5 calculation | **Active** | Streaming hash calculation for readable APKs and selected files. Hash calculation alone is not detection. |
| Permission and manifest risk | **Heuristic** | Uses visible package permissions, service metadata and risk combinations to flag review candidates. This is not a trained classifier and may miss malware or flag benign apps. |
| Root, Magisk, Xposed/LSPosed, build properties, SELinux, debugger and emulator signals | **Heuristic** | Offline best-effort signals influence app triage risk. These are bypassable and cannot prove the OS is trusted. |
| Bloom filter | **Disabled in the scan path** | A manifest- and SHA-256-verifying loader exists, but a valid non-empty `hypatia_bloom.db` and corresponding manifest are not shipped or wired into the normal package scan. |
| YARA / DEX / assets | **Disabled** | No built libyara JNI runtime or curated, licence-reviewed rule set is bundled. The API reports disabled rather than pretending to scan. |
| TFLite permission model | **Disabled / fallback** | The optional TFLite runner exists, but the trained and evaluated `permission_risk.tflite` asset is absent. No model inference is claimed; heuristic triage remains the fallback. |
| Offline signer attestation | **Not activated** | Helper code compares the APK signer/asset digest to an independently supplied expected SHA-256, but no trusted release-signer pin is configured or enforced in the normal scan path. |
| Signed feed | **Implemented conditionally; no production feed configured** | The feed importer has Ed25519 manifest verification, payload-digest binding, monotonic version checks and explicit consent. It needs an operator-managed public key and a licensed, signed publisher feed before it can run. |
| Quarantine | **Implemented with constraints** | Selected/quarantined content is encrypted using Tink Streaming AEAD with an Android Keystore-wrapped keyset and hash/length integrity checks. Legacy entries may be unencrypted; original files are not always removed. |

More detail and release conditions are in [docs/DETECTION_COVERAGE.md](docs/DETECTION_COVERAGE.md), [docs/MODEL_CARD.md](docs/MODEL_CARD.md), and [docs/ATTESTATION.md](docs/ATTESTATION.md). Do not describe Bloom, YARA, TFLite, or signer attestation as active until the required artefacts and end-to-end call paths are shipped and tested.

## Storage, backup and data at rest

- Android's backup attributes are set to `allowBackup=false`, `fullBackupContent=false`, `dataExtractionRules` excludes the app's root/files/database/shared-preferences/external domains from cloud backup and device transfer, and `hasFragileUserData=false` is set.
- These settings are checked in the manifest/artifact CI gate. **The maintainers have not performed a physical-device `adb backup` / restore-extraction test in this change.** Modern Android backup behavior differs by OS version and OEM, so do not claim that a device-level test has passed.
- New quarantine files are encrypted and hash-verified. The Room database itself is **not SQLCipher-encrypted**. New scan labels, install/download incident names and paths, and new quarantine database labels/paths are field-encrypted with Tink AES-SIV using a Keystore-wrapped keyset; the reader keeps legacy plaintext rows readable. Timestamps, verdicts, session/event IDs, status fields and other database structure are still not encrypted as a whole. Do not describe the entire database as encrypted or PII-free; minimization/retention or a whole-database encryption decision remains a release gate.
- Downloads monitoring and shared-file scanning are scoped to a folder chosen by the user in Android's Storage Access Framework (SAF) picker. The app persists that folder grant; full scan traverses only that tree, with a limit of 10,000 items and four directory levels per pass. Without a selected/granted folder, the installed-app scanner still works but a full scan does not enumerate shared storage. The app no longer requests `MANAGE_EXTERNAL_STORAGE` or `READ_EXTERNAL_STORAGE`.
- Revoking the selected folder grant or stopping the monitor removes the monitor's ability to read that folder. The user can stop monitoring in the UI.

## Restricted permissions and Play review

`QUERY_ALL_PACKAGES` remains in the base manifest because the core installed-app scan enumerates visible installed packages. A prominent disclosure is shown before a sensitive scan action. This does **not** guarantee Google Play eligibility. Complete the Permissions Declaration Form honestly and await Play's review. See [docs/PLAY_PERMISSIONS.md](docs/PLAY_PERMISSIONS.md). The broad all-files permission was removed in favor of SAF folder access.

Play Console version-code history is a manual pre-release check: the version-code script can compare repository tags, but it cannot query the Play Console or prove that code 20261023 has never been used.

## Threat feed protocol

The runtime defaults to no feed sync. To build a feed variant, supply the trusted **raw 32-byte Ed25519 public key encoded as Base64** through `SAFE_MOBILE_FEED_ED25519_PUBLIC_KEY_B64`. Keep the private signing key in a separate controlled publisher system; never put it in Gradle source, the APK or repository variables that are accessible to untrusted builds.

Feed responses must include `X-SafeMobile-Manifest` and `X-SafeMobile-Signature`. The manifest is Base64 of the exact signed UTF-8 JSON bytes and binds `schema_version`, monotonic `version`, `source_key` (SHA-256 of configured HTTPS URL), and `sha256` (the uncompressed response body digest). A response must be signed, point to the configured source, match the body digest and have a version greater than the last accepted value. See [docs/THREAT_FEED_SIGNING.md](docs/THREAT_FEED_SIGNING.md).

## Build and test

Use JDK 17, Android SDK tools for API 36, and the checked-in Gradle wrapper.

```bash
# Unit tests
./gradlew --no-daemon testOfflineDebugUnitTest

# Lint both network variants
./gradlew --no-daemon lintOfflineDebug lintFeedDebug

# Recommended no-Internet build
./gradlew --no-daemon assembleOfflineDebug assembleOfflineRelease bundleOfflineRelease

# Only when the optional feed variant is intentionally required
./gradlew --no-daemon assembleFeedRelease bundleFeedRelease

# Instrumented tests (requires a running compatible emulator)
./gradlew --no-daemon connectedOfflineDebugAndroidTest

# Version guard and repo policy checks
python3 scripts/check_version_code.py
python3 scripts/check_proprietary_safety.py
python3 scripts/check_release_docs.py
```

CI additionally generates a CycloneDX BOM from the resolved Gradle dependency graph, inspects release manifests/DEX bytecode, and defines local Android emulator jobs for API 26, 30, 34 and 36. Instrumented jobs must pass before merging. The data-extraction attributes must also be verified on devices; manifest inspection is not a substitute for a device backup test.

Release signing needs all four environment variables / GitHub Actions secrets: `KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, and `KEY_PASSWORD`. Without them, build output is unsigned and cannot be uploaded to Play. Do not commit keystores or secrets.

## Release gates that remain open

1. **Detection data:** acquire/verify redistribution rights for an actual feed, generate and sign a reproducible hash index, and add known-bad/known-good regression tests. No real-world malware database is bundled today.
2. **YARA:** build/review native libyara libraries for the supported ABIs, bundle permitted rules and test bounded timeout/resource behavior. No YARA scan occurs today.
3. **ML model:** train or obtain a permitted model, evaluate it on separated benign/malicious families, publish data/metrics/false-positive limits, and only then wire inference to the scanner.
4. **Attestation:** pin the expected release signer through independently trusted build configuration and enforce the comparison in the release/scan flow.
5. **Privacy:** encrypt the Room database or minimize/retention-limit the stored identifying fields; add a debug socket-attempt monitor/test; perform device backup/restore checks.
6. **Feeds:** configure the publisher key, validate the end-to-end server signing process, document provider terms and publish a signed initial snapshot or leave syncing disabled.
7. **QA:** complete local emulator runs on API 26/30/34/36, quarantine round-trip/device testing, large-feed/redirect/outage cases and native-speaker review of every shipped locale.
8. **Compliance:** run the SBOM refresh, resolve unknown licence/source metadata, submit the `QUERY_ALL_PACKAGES` declaration, and manually check Play Console version usage and policy decisions.

Use [docs/RELEASE_GATES.md](docs/RELEASE_GATES.md) to track pass/fail status. Until those gates close, distribute only to testers with accurate coverage disclosures; do not market the build as an alternative to a mature commercial antivirus.

## Licence and contributions

Project source is licensed under the [Apache License 2.0](LICENSE). Third-party packages, model data, threat feeds and rules retain their own terms; the root licence does not grant redistribution rights to external datasets or materials. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), [docs/PROPRIETARY_AND_LICENSE_POLICY.md](docs/PROPRIETARY_AND_LICENSE_POLICY.md), and [docs/sbom.json](docs/sbom.json) when the generated SBOM is materialized by CI. Missing SBOM metadata or incomplete notices remain release blockers.

Please submit changes through feature branches and reviewable pull requests. Do not add real malware samples, unreviewed threat datasets, private signing keys, keystores or credentials to this repository.
