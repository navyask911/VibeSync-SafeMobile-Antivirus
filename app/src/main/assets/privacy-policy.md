# SafeMobile Antivirus — Privacy Notice

**Last reviewed:** 22 October 2026. This is a code-based privacy description, not independent network/backup testing or legal advice.

## Local scanning and audit data

SafeMobile reads visible installed-package metadata and APK paths that Android makes readable, or hashes files that the user selects with Android's system picker. Hashing and local hash lookups run on-device; the scanner does not intentionally upload APK contents, scan file hashes, package inventory, scan results or history. The current bundled baseline contains only the harmless EICAR test-marker signature, so a no-match result does not guarantee safety.

The app stores a local Room scan history. New package/file labels and install/download incident names and paths are encrypted field-by-field with Tink AES-SIV using a Keystore-wrapped keyset and distinct associated data. Old database rows remain backward-compatible and may retain plaintext labels until deleted or overwritten. Timestamps, verdicts, durations, scan-session IDs, event IDs, status values and other fields are not encrypted as a database. Room is **not SQLCipher-encrypted**, so it is inaccurate to say the entire database or all stored metadata is encrypted or that the app stores only hashes. Records remain in app-private storage; data minimization/retention or a whole-database encryption decision is still required for stronger privacy guarantees.

## Optional shared-folder monitoring

Downloads monitoring is off unless the user enables it. The user chooses a folder through Android's Storage Access Framework document picker; SafeMobile persists access only to that selected folder and polls it locally at bounded depth. Full scan visits only that selected tree, limited to 10,000 entries and four directory levels per pass; without a selected/granted folder, installed-app scanning works but shared storage is not enumerated. The manifest does not declare `MANAGE_EXTERNAL_STORAGE` or `READ_EXTERNAL_STORAGE`. The user can stop the foreground monitor or revoke its selected-folder grant in Android settings.

## Quarantine

New quarantine payloads are stored in an app-private no-backup directory encrypted with Tink Streaming AEAD and a keyset protected by Android Keystore. The source/destination data is hash-checked during quarantine and restore. The original source is deliberately retained by the selected-file quarantine path unless a separate supported action removes it. Older quarantine entries may have been created without encryption by a prior build and remain a migration/review concern.

## Internet, telemetry, and feed variant

The app source removes Mobile Ads, UMP consent, analytics, telemetry, crash-reporting and Google Play In-App Updates SDKs from the Android application variants. The `offline` flavor omits `android.permission.INTERNET`, and is the recommended build for the default offline use case. Core scanning and local storage do not need cloud services.

The `feed` flavor adds `INTERNET` only to support an optional HTTPS threat-feed importer. It does not schedule or accept a sync unless the user saves a configured endpoint, enables the in-app opt-in after seeing its disclosure, and the build contains a configured trusted Ed25519 public key. Requests necessarily contact that feed endpoint, so that provider can observe connection metadata and any configured provider authentication token sent with the request. The protocol requires a detached signature over a manifest binding the source URL, monotonically increasing version, and body SHA-256. Scan files, hashes, package inventory and history are not intentionally sent as feed request content. The app has no configured production feed key or real signed snapshot in this candidate; a build without the key rejects remote sync.

The offline artifact's manifest and release bytecode are checked in CI for no Internet permission and known ad/analytics/crash SDK markers. This CI check is not packet-capture evidence and does not prove that every device/OEM backup or socket path behaves identically. Device-level no-backup/network tests remain release gates.

## Android backup

The manifest declares backup disabled and the Android 12+ data-extraction rules exclude app-data domains from cloud backup and device transfer. `hasFragileUserData` is false. This code configuration has not yet been verified with a physical-device `adb backup`/restore extraction. Modern Android versions may disable legacy adb backup behavior, so a test result must identify the tested API/device and method.

## Permissions and Play review

`QUERY_ALL_PACKAGES` is declared for the user-visible installed-app antivirus scan. The in-app disclosure explains the on-device purpose and data flow. Downloads monitoring uses the scoped document picker instead of broad all-files access. These choices do not guarantee Google Play approval; declarations, privacy forms and review outcome are the maintainer's responsibility.

## Third-party licences

The project source uses Apache License 2.0. Third-party dependencies and data feeds retain their separate licences/terms. Review `THIRD_PARTY_NOTICES.md`, the generated `docs/sbom.json` after CI materializes it, and `docs/PROPRIETARY_AND_LICENSE_POLICY.md`. A missing licence field is not approval to redistribute a component or dataset.
