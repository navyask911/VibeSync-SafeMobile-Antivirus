# VibeSync SafeMobile Antivirus

Native Android Kotlin app using Jetpack Compose Material 3, Room, WorkManager, Google Tink and StateFlow-based MVVM.

## Build settings
- Application ID: com.vibesync.antivirus
- Min SDK 26; compile and target SDK 35
- JDK 17, Gradle Kotlin DSL
- Version name 1.0.0; version code 20261020. Increase versionCode for each subsequent Play release.
- CI runs tests and lint, then builds debug and release APKs plus a release AAB. If the four standard KEYSTORE_* / KEY_* GitHub Actions secrets are configured, release APK/AAB outputs are signed; otherwise they remain unsigned.

## Privacy boundary
Hashing, local signature matching, permission heuristics, scan audit storage and scheduled scans are on-device. The scanner does not send files or hashes to a server. There is no telemetry, analytics, crash reporting, remote threat feed, Supabase or VirusTotal client. Google Mobile Ads and UMP are included because ad units were explicitly requested; these SDKs may communicate with Google when connectivity and the user's consent state permit. Google Play In-App Updates also contacts Google Play. The app’s core scan functions do not depend on those network features and continue to run without connectivity.

## Important antivirus limitation
The bundled offline-threat-definitions.json contains only the SHA-256 signature of the harmless EICAR antivirus test marker so the hash matching path can be checked end to end. It is not a real malware dataset and does not provide meaningful protection against actual threats. The UI warns about this. A document-picker import accepts a local JSON file with a definitions array (sha256, malware_family, threat_level, date_added); only import a curated, legally distributable and validated signature dataset. No remote definition feed is implemented. Do not advertise this build as comprehensive protection or publish it as a finished commercial antivirus until real local definitions, provenance/licensing, false-positive testing and a physical-device test matrix are completed.

Android sandboxing prevents third-party apps from scanning arbitrary system partitions. This app scans readable installed APK paths, user-selected files, and (with explicit all-files access) a bounded set of APKs under Downloads. The install receiver can only perform a best-effort post-install check; it cannot intercept/block installation before Android installs the package. WorkManager offers a battery-not-low constraint, not a general device-idle constraint.

QUERY_ALL_PACKAGES and MANAGE_EXTERNAL_STORAGE are restricted Google Play permissions. Declaration does not guarantee approval. Complete Play Console declarations and confirm eligibility for the core security use case. The privacy dialog is an acknowledgement; it does not grant Android special permissions or guarantee Play approval.

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
