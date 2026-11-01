# SafeMobile Antivirus — Privacy Notice

Last reviewed: 26 October 2026.

## Local scanning and data
SafeMobile hashes readable installed APKs and files you explicitly select, then compares hashes against definitions stored in the app's local database. Scan contents and hashes are not uploaded by the scanner. When connected, WorkManager may request the latest signed database from this project's GitHub Releases API; the bundle is signature-verified before activation. The app never queries MalwareBazaar directly. A no-match result is not proof that a file is safe. Production APK/AAB artifacts do not bundle the signed threat database.

The app stores recent scan audit records in its private Room database. Records include the package/file display identifier, timestamp, verdict, duration, scan-session identifier, and a protected hash value when available. Scan history is local to the app. The app does not offer a complete audit export or configurable retention policy in this build. Android backup is disabled in the manifest and extraction rules.

## Files and installed applications
SafeMobile requests installed-package visibility for scanning, source review and device permission audits. The user may select an individual file or folder using Android's system picker. Downloads monitoring is optional and only runs after the user enables it. Android limits access to protected directories; not every WhatsApp or Telegram path can be inspected on every device.

The storage cleaner examines APK metadata in a folder the user explicitly selects. It copies APK data temporarily into the app cache for metadata inspection, then deletes those temporary copies. Cleanup candidates are not automatically treated as malicious. A deletion is performed only after the user confirms the exact selected set, and the cleaner rechecks the current document metadata where the provider exposes it.

## Device Posture and Loophole Monitor
Device Posture reads metadata about enabled accessibility services, active administrators, notification listeners and visible overlay permission states in the current Android profile. It shows app names, package/component identifiers, permission status and system-app classification. It does not read screens, message contents or notifications, bind to these services, automate clicks, revoke permissions or change device policies. HIGH RISK describes a powerful capability, not proof of spyware. Android and OEM restrictions may limit coverage; unavailable metadata is labelled accordingly.

After the privacy disclosure is accepted, the optional Loophole Monitor compares accessibility, administrator and notification-listener access about every six hours, subject to Android background scheduling. Its first successful comparison establishes a silent baseline. A monitor toggle is available on Device Posture. Change notifications respect the separate Security Alerts opt-in and Android notification controls. Dashboard findings do not require notification permission.

The monitor stores package/capability identifiers, initialized categories, comparison timestamps and pending change timestamps locally using Tink AES-256-GCM with an Android Keystore-wrapped keyset. It refuses unprotected-keyset fallback. Snapshot ciphertext is atomically written in app-private no-backup storage. It contains no screen, message or notification contents and no app display names. Pending changes are retained until delivered or observed revoked. Non-sensitive local preferences contain the monitor toggle and numeric health counters. This module sends nothing to a server. Clearing app data or uninstalling removes this local state.

## Quarantine
New quarantine items are stored in app-private no-backup storage using Tink Streaming AEAD with an Android Keystore-wrapped keyset. The app verifies source hashes and decrypted content before reporting success. The original file is intentionally retained; restoring writes a verified copy to a location the user chooses. Legacy pre-hardening quarantine entries may be unencrypted and are labelled accordingly.

## Network access and privacy boundary
The scanner does not submit file contents, hashes, filesystem paths, permission snapshots or scan history to a developer-operated server by default. The Free tier uses Google AdMob; Google may process the Advertising ID and IP address for ad delivery and fraud prevention. While SafeMobile Pro is active, SafeMobile does not initialize AdMob and does not request or display ads. Active SafeMobile Pro disables AdMob initialization, ad preloading, ad requests and ad display. Pro status is checked before initialization, each banner load and each interstitial show; if status cannot be verified, ads remain disabled. UMP privacy choices are refreshed before ad requests, and an in-app privacy-options entry point is shown whenever UMP requires one. Both variants use INTERNET for signed definition downloads from this project's GitHub Releases. Existing local definitions can be used without a network connection.

The separate `feed` flavor supports optional HTTPS threat-feed synchronization. That optional feed does not make requests unless the user saves an endpoint, enables the explicit in-app network-consent switch, and a trusted Ed25519 public verification key was configured at build time. Every successful response requires a detached Ed25519 signature binding the configured source, a strictly newer version, and the response body's SHA-256. Scan results and files are not uploaded by feed synchronization.

There is no automatic link-reputation lookup, cloud scanning, or Google Play update client. The Free tier includes Google AdMob; active SafeMobile Pro is exempt from AdMob requests and ad display.

### Optional Global Threat Intelligence contributions

Global Threat Intelligence is **OFF by default**. Enabling its Settings switch does not send data. For each confirmed malicious APK, SafeMobile asks separately; only a Donate tap while the master switch remains enabled starts an HTTPS request to the VibeSync Cloudflare Worker. The JSON contains only the detected malware SHA-256 hash and its exact 215-value binary behavioral feature vector. The APK itself is never uploaded. No filename, filesystem path, package/app name, scan history, account identity, Android ID, device fingerprint, contacts, messages or location is included. No GitHub token or other GitHub credential is embedded in the Android app.

The client checks that the APK still matches its locally detected hash before and after feature extraction. Unscannable, changed or invalid APKs are not submitted. Failures are non-blocking and do not interrupt scanning. Cloudflare and network infrastructure may process ordinary connection metadata such as IP address; that metadata is separate from the JSON payload. Worker-side logging and retention are controlled by the Worker operator and are not independently audited by this client.

### Optional SafeMobile Pro purchases

Opening the Pro paywall connects to Google Play to retrieve its current price and process
pending purchases. Google Play handles payment and purchase consumption under its own terms
and privacy policy. Core antivirus checks remain free and run on-device. Optional model
downloads use a network connection and do not upload scan files or results.

The Pro entitlement is stored locally in Keystore-encrypted preferences, bound to a hash of
the app-scoped Android ID. SafeMobile does not send that binding, scan files, scan history,
or purchase tokens to a developer-operated server. Consumed passes cannot be restored by
Google Play after uninstalling, clearing app data, device reset or encryption-key loss.
The paywall discloses these limitations before purchase and provides a local-only status check.

## Permissions and controls
The base manifest declares package and network-state visibility, INTERNET for definition synchronization, foreground-service and notification permissions, and optional alert/device-administration integrations. File access uses the system picker and persisted grants to selected folders. Android settings and runtime permission prompts remain controlled by the operating system. SafeMobile cannot universally block sideloads, force-stop other apps, disable global Developer Options/ADB, intercept all links in other browsers, or guarantee malware detection.

## Third-party licences
THIRD_PARTY_NOTICES.md is an audit checkpoint, not a complete set of all dependency licence texts. The repository root LICENSE describes the project's licence. The maintainer must complete the direct and transitive dependency licence audit before commercial distribution.
