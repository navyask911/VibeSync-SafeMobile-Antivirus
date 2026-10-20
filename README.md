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
- The selected-file scanner refuses cloud and third-party document providers before opening their content. Supported local document providers can be copied to app-private, no-backup quarantine storage.
- After the private copy's SHA-256 is verified against the scan result, SafeMobile makes a best-effort request to delete the selected original. Android or the provider may deny that request; the UI distinguishes this outcome. Quarantine copies remain in private app storage. The hardening branch adds a Quarantine Vault to list isolated copies, restore a copy to a user-selected destination (retaining the quarantined copy), or permanently delete a copy after confirmation.

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

The current translated resource folders cover Arabic, German, Spanish, French, Hindi, and Japanese, in addition to default English resources. The updated scan/quarantine strings are translated for those existing locales. The full additional language coverage requested for a global launch (including Portuguese, Russian, Simplified Chinese, Korean, Turkish, Indonesian, Vietnamese, Italian, and further Indian locales) and an in-app language override are not yet implemented. Do not claim complete global localization until those translations and locale behavior are verified.

### Release caveats

This branch has a higher version code, but Play Console's usage history must be checked before upload. A passing build does not mean the proprietary dependency licence review, remote definition signing pipeline, threat-feed redistribution rights, physical-device QA, broad-permission eligibility, or complete global localization is finished.
