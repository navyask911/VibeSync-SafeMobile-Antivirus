# VibeSync SafeMobile Antivirus

Native Android Kotlin app using Jetpack Compose Material 3, Room, WorkManager, Google Tink and StateFlow-based MVVM.

## Build settings
- Application ID: com.vibesync.antivirus
- Min SDK 26; compile and target SDK 35
- JDK 17, Gradle Kotlin DSL
- Version name 1.0.1; version code 20261021 on the hardening branch. Check Play Console before release because repository history cannot establish whether a code was already used there.
- CI runs tests and lint, then builds debug and release APKs plus a release AAB. If the four standard KEYSTORE_* / KEY_* GitHub Actions secrets are configured, release APK/AAB outputs are signed; otherwise they remain unsigned.

## Privacy boundary
Hashing, local signature matching, permission heuristics, scan audit storage and scheduled scans are on-device. The scanner does not send files or hashes to a server. There is no telemetry, analytics, crash reporting, remote threat feed, Supabase or VirusTotal client. Google Mobile Ads and UMP are included because ad units were explicitly requested; these SDKs may communicate with Google when connectivity and the user's consent state permit. Google Play In-App Updates also contacts Google Play. The app’s core scan functions do not depend on those network features and continue to run without connectivity.

## Important antivirus limitation
The bundled offline-threat-definitions.json contains only the SHA-256 signature of the harmless EICAR antivirus test marker so the hash matching path can be checked end to end. It is not a real malware dataset and does not provide meaningful protection against actual threats. The UI warns about this. A document-picker import requires schema_version 1 and a non-empty definitions array with valid unique SHA-256 values, supported threat levels, labels and positive timestamps. This validates the file structure; it does not authenticate who created the file. The UI now warns users before importing unauthenticated definitions. No remote definition feed or online reputation client is implemented. Do not advertise this build as comprehensive protection or publish it as a finished commercial antivirus until real local definitions, source provenance/licensing, false-positive testing and a physical-device test matrix are completed.

Android sandboxing prevents third-party apps from scanning arbitrary system partitions. This app scans readable installed APK paths, user-selected files, and (with explicit all-files access) a bounded set of APKs under Downloads. The install receiver can only perform a best-effort post-install check; it cannot intercept/block installation before Android installs the package. WorkManager offers a battery-not-low constraint, not a general device-idle constraint.

QUERY_ALL_PACKAGES and MANAGE_EXTERNAL_STORAGE are restricted Google Play permissions. Declaration does not guarantee approval. Complete Play Console declarations and confirm eligibility for the core security use case. The privacy dialog is an acknowledgement; it does not grant Android special permissions or guarantee Play approval.

## Flagged-result actions
- Flagged installed apps show an Uninstall action that launches Android's own confirmation UI; the app cannot silently remove an app or block installation.
- The selected-file scanner only opens content from explicitly recognized on-device provider authorities; it refuses unknown/cloud providers rather than assuming that every content URI is local.
- Current quarantine entries use Google Tink Streaming AEAD with an Android Keystore-wrapped keyset, are encrypted in app-private no-backup storage, and are checked by streaming SHA-256 during copy. Before reporting success, SafeMobile decrypts the new object in a verification pass and checks the hash and length. Restore decrypts into a temporary private file, verifies the expected hash/length, writes to a user-selected destination, and reopens that destination to verify its SHA-256. The quarantined object remains until explicitly deleted.
- SafeMobile deliberately does **not delete the selected original** during quarantine. The user must decide separately how to remove it using Android's supported file-management UI. Legacy quarantine entries created by earlier builds can still appear in the vault, but are clearly labelled as unencrypted; their past contents cannot be retroactively protected.

## Ads
The app-ads.txt publisher ID alone does not identify an AdMob app or its ad units. To avoid embedding unverified production IDs, release builds keep ads disabled unless all three GitHub Actions repository variables are configured: ADMOB_APP_ID, ADMOB_BANNER_UNIT_ID, and ADMOB_INTERSTITIAL_UNIT_ID. Set those values from the actual AdMob dashboard. Debug builds always use Google's official test app/ad IDs. When production IDs are configured, UMP consent gates SDK initialization/ad requests. When they are absent, the release does not initialize Mobile Ads and makes no ad requests. The adaptive banner is anchored in the dashboard footer. Interstitials are only considered after every third completed scan, not on app launch or mid-scan. Configure privacy messages in AdMob and do not click production ads during testing.

## In-app updates and coffee support
The app checks Google Play in-app updates on launch and foreground return. Priority 4+ or updates stale by at least seven days prefer the immediate flow when allowed; otherwise flexible flow is used. This API depends on Google Play installation/update availability. The coffee sponsorship action opens a secure external browser link when the user is online; it is not part of scanning.

## app-ads.txt
The exact authorized seller line exists at the repository root. This does not host it on your public website by itself. Copy app-ads.txt to the root of the website domain entered in AdMob, then verify that https://YOUR-DOMAIN/app-ads.txt returns HTTP 200, Content-Type text/plain, without redirects or authentication. No public website domain was provided, so live URL/status verification is still outstanding.

## Build commands
./gradlew testDebugUnitTest
./gradlew lintDebug
./gradlew assembleDebug assembleRelease bundleRelease

Release APK and AAB outputs are signed only when all four repository Actions secrets are set: KEYSTORE_BASE64 (base64-encoded keystore), KEYSTORE_PASSWORD, KEY_ALIAS, KEY_PASSWORD. Never commit the keystore or passwords. If the secrets are absent, CI creates unsigned artifacts that are not Play-upload-ready. Before production release, add a real offline definition set, test on physical Android versions, evaluate Play restricted-permission requirements, and verify consent/localization and update flows.

## Hardening branch changes and limitations

The feature branch `feat/safemobile-proprietary-hardening-20261021` adds installed-app scan progress and a Cancel action; mutually exclusive Downloads Sentinel Enable/Stop controls reflecting observed service state; an unverified-definition import warning; stricter whole-file definition validation; a Quarantine Vault with explicit restore/delete confirmations; SMS plus network/accessibility permission-combination risk indicators; and a CI safety guard. These changes remain separate from `main` until review and CI verification.

The scanner's heuristic results are review indicators, not proof that an app is malware. SafeMobile does not inspect SMS or OTP content, collect credentials, or implement an app-spying AccessibilityService.

### Proprietary and third-party licence status

The repository was publicly visible and had no root `LICENSE` file at the reviewed baseline. Public visibility makes the source readable; it does not itself grant third parties an open-source licence, but it also means the source is not confidential. The owner must decide whether to keep the repo public or make it private and document an intentional licensing policy. No ClamAV native engine, VirusTotal Public API client, YARA runtime, MalwareBazaar/URLhaus client, or remote signature feed is added by the hardening branch. Exact direct and transitive dependency licences and required notices remain to be audited before commercial release; see `docs/PROPRIETARY_AND_LICENSE_POLICY.md`, `docs/THREAT_INTELLIGENCE_STATUS.md`, and `THIRD_PARTY_NOTICES.md`.

### Localization status

The app now has full application-string resource files and an in-app locale override for English, Arabic, German, Spanish, French, Hindi, Japanese, Portuguese, Russian, Simplified Chinese, Korean, Turkish, Indonesian, Vietnamese, Italian, Kannada, Tamil, Telugu, Bengali, Marathi, Urdu, and Hebrew. The added translations are first-pass drafts and need native-speaker review, particularly security/privacy wording and RTL layouts, before production. Locale-resource checks verify key coverage and formatted-placeholder parity; that does not certify translation quality or on-device layout. The current selector includes these locales plus System default.

### New hardening-branch security screens

The feature branch adds a globe-based app-language selector using the existing persisted locale override, an expandable feature overview, a Guardian screen for best-effort installed-app installer-source review and read-only Developer Options/ADB status, a local URL-risk checker reachable from Android's share sheet, and a Storage Access Framework APK metadata cleaner. The cleaner requires the user to select a folder and to confirm deletions; inaccessible package metadata is treated as unknown, not evidence that a package is absent. The About & Legal dialog reads a bundled README, privacy notice, and third-party licence checkpoint, and Settings includes the requested family dedication.

A separate random UUIDv4 threat-event Ray ID is generated for each confirmed local signature match, persisted in scan history, and shown with the result. Historical audit rows keep an empty event ID; no historical IDs are fabricated. A candidate release uses versionName 1.0.2 and versionCode 20261022, which must still be checked against Play Console history before upload.

## Release caveats

This branch has a higher version code, but Play Console's usage history must be checked before upload. A passing build does not mean the proprietary dependency licence review, remote definition signing pipeline, threat-feed redistribution rights, physical-device QA, broad-permission eligibility, or complete global localization is finished.


## UI and review features on the hardening branch

- The dashboard now uses a compact status surface with separate Home, Scan, Quarantine, History, and Settings destinations. The product title no longer shares a row with the locale selector.
- System, Light, and Dark appearance choices are persisted locally. Locale overrides are available from Settings. New navigation, settings, and overlay-review strings have first-pass translations in the existing 22 locale resource sets; native-speaker and device-layout review remains outstanding.
- Scan history groups audit rows by a unique scan-session UUID while preserving older rows through an additive Room migration. Each assessment row remains local. The history view currently shows the newest retained audit rows and should not be interpreted as a complete forever-retained archive or server-registered support log.
- A locally generated UUIDv4 SafeMobile Ray ID is shown in Settings. It is stored locally and is not sent to an external registration service by the scan engine.
- The optional Overlay-risk review is off by default. When enabled, WorkManager attempts a best-effort review on foreground return and on a nominal 12-hour periodic interval, subject to Android scheduling and battery constraints. It counts package declarations of overlay capability/accessibility services and counts enabled accessibility-service entries reported by Android. It cannot see live overlay activity, determine another app's actual overlay-grant state, or prove malware. Reminders are low priority and follow the selected 12/24/48-hour interval when notifications are permitted.
- A first-run legal wall no longer blocks ordinary navigation. The privacy/scan-access disclosure is shown when the user initiates installed-app scanning, selected-file scanning, definition import, or Downloads monitoring; this acknowledgement does not itself grant operating-system permissions or constitute advertising consent.

## Current verification boundary

These changes are being validated in the draft pull request. CI checks (safety guard, tests, lint, and release builds) must pass on the final head before considering a candidate verified. No physical-device/emulator test matrix has been run as part of this source edit. The EICAR-only definition database, restricted-permission Play review, exact third-party license/SBOM audit, and native-speaker localization review remain release blockers. The configured version code and CI signing-secret state are not proof that Google Play will accept the candidate; check the Play Console version history before upload.


## Configurable local threat-intelligence synchronization

The hardening branch adds a separate indexed malware_hashes table for SHA-256, MD5 and network indicators (domain/IP/URL), plus per-source synchronization state. Existing encrypted offline threat_signatures, scan audits and their historical data are preserved by the additive Room 3-to-4 migration.

Threat feeds are not enabled by default. In Settings, configure a trusted HTTPS JSON or CSV endpoint and an optional provider Auth-Key. The Auth-Key is encrypted locally using an Android Keystore AES-GCM key; it is not placed in source code, BuildConfig, or logs. The worker accepts GET or JSON POST, follows only HTTPS redirects, will not forward an Auth-Key to another host, caps decoded feed input at 128 MiB, caps CSV field/record size, and streams rows in batches of 500 inside Room transactions. A sync requires an unmetered network and device charging; periodic sync is scheduled every 24 hours. Transient network errors retry, while malformed/auth-rejected responses report failure and retain existing local indicators.

The parser accepts JSON arrays and common objects containing data/results arrays, nested malware sample hash records, and quoted CSV with escaped quotes and multiline fields. Hash lookups use indexed local-only suspend DAO queries. The dashboard exposes the local indicator count and last successful sync time. A matching imported hash is a feed match, but no feed guarantees comprehensive detection. Choose a provider whose access terms permit the intended use and supply your own authorized key when required. The app does not bundle a vendor credential or download malware samples.
