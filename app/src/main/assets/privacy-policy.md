# SafeMobile Antivirus — Privacy Notice

Last reviewed for the current hardening branch: 21 October 2026.

## Local scanning and data
SafeMobile hashes readable installed APKs and files you explicitly select, then compares hashes against definitions stored in the app's local database. Scan contents and hashes are not uploaded by the scanner. This build's bundled definitions include only the harmless EICAR antivirus test marker; a no-match result is not proof that a file is safe.

The app stores recent scan audit records in its private Room database. Records include the package/file display identifier, timestamp, verdict, duration, scan-session identifier, and a protected hash value when available. Scan history is local to the app. The app does not offer a complete audit export or configurable retention policy in this build. Application data is not intended to be backed up (Android backup is disabled in the manifest).

## Files and installed applications
SafeMobile requests installed-package visibility for its scan and source-review features. The user may select an individual file or folder using Android's system picker. Downloads monitoring requires the user to enable it and may ask for all-files access on Android versions that require it. Android limits access to protected directories; not every WhatsApp or Telegram path can be inspected on every device.

The storage cleaner examines APK metadata in a folder the user explicitly selects. It copies APK data temporarily into the app cache for metadata inspection, then deletes those temporary copies. Cleanup candidates are not automatically treated as malicious. A deletion is performed only after the user confirms the exact selected set, and the cleaner rechecks the current document metadata where the provider exposes it.

## Quarantine
New quarantine items are stored in app-private no-backup storage using Tink Streaming AEAD with an Android Keystore-wrapped keyset. The app verifies source hashes and decrypted content before reporting success. The original file is intentionally retained; restoring writes a verified copy to a location the user chooses. Legacy pre-hardening quarantine entries may be unencrypted and are labelled accordingly.

## Network access and privacy boundary

The scanner does not submit file contents, hashes, filesystem paths, or scan history to a server. This project removes ad/consent SDKs, analytics, telemetry and crash-reporting clients from all application variants. The `offline` flavor (the recommended default for distribution) omits the Android `INTERNET` permission. It can scan and store results locally without a network connection.

The separate `feed` flavor adds `INTERNET` for optional HTTPS threat-feed synchronization. It does not schedule or make requests unless the user saves an endpoint, enables the explicit in-app network-consent switch, and a trusted Ed25519 public verification key was configured at build time. Every successful response requires a detached Ed25519 signature binding the configured source, a strictly newer version, and the response body's SHA-256. Scan results and files are not uploaded by feed synchronization. Do not distribute the feed flavor with sync enabled until the key and publisher/signing process have been reviewed.

There is no automatic link-reputation lookup, cloud scanning, Google Play update client, mobile-ad SDK, or in-app sponsorship request in these application variants.

## Permissions and controls
The base manifest declares package visibility, network-state visibility, legacy external-storage access, all-files access for the optional Downloads monitor, foreground-service and notification permissions. Only the separate feed flavor declares INTERNET. Android settings and runtime permission prompts remain controlled by the operating system. SafeMobile cannot universally block sideloads, force-stop other apps, disable global Developer Options/ADB, intercept all links in other browsers, or guarantee malware detection.

## Third-party licences
THIRD_PARTY_NOTICES.md is an audit checkpoint, not a complete set of all dependency licence texts. The repository baseline reviewed for this branch has no root LICENSE file. The maintainer must complete the direct and transitive dependency licence audit before commercial distribution.
