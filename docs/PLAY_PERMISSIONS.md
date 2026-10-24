# Google Play restricted-permission justification and disclosure

Reviewed: 2026-10-22. This document records the intended app behavior; it is not a statement that Play Console has approved the declaration.

## QUERY_ALL_PACKAGES — retained only for the core antivirus scan

Google Play explicitly lists antivirus apps as a potentially permitted use, but eligibility depends on broad visibility being core functionality, an accurate Permissions Declaration Form, and compliance with User Data and prominent-disclosure requirements. Broad package visibility exposes installed-app inventory, which Play treats as sensitive user data. Policy reference: https://support.google.com/googleplay/android-developer/answer/10158779

**Declaration draft (verify and paste/adapt in Play Console):**

> SafeMobile is an Android antivirus app. The user can start a local scan of installed applications. The scanner must enumerate installed packages, inspect readable APK/manifest metadata and calculate local hashes to compare with local threat definitions. The package inventory is used only to provide the requested on-device security scan. Installed package names, APKs, hashes, scan results and history are not transmitted, sold or shared for advertising or analytics. Targeted package queries do not provide the breadth required for an all-installed-app antivirus scan. Users see a prominent disclosure before starting an installed-app scan.

This is proposed declaration language, not “exact required wording”: Google Play assesses the truth and necessity of the submitted use case and may require changes or deny the request. Keep `QUERY_ALL_PACKAGES` only while this remains the app's core user-facing functionality. Do not use inventory for analytics, ads, marketing, monetization or remote telemetry.

## MANAGE_EXTERNAL_STORAGE — removed

The manifest no longer declares `MANAGE_EXTERNAL_STORAGE` or `READ_EXTERNAL_STORAGE`. The optional Downloads Sentinel uses the Storage Access Framework. The user explicitly selects a folder in the Android document picker; SafeMobile persists access to that folder only and polls it while monitoring is enabled. Core installed-app scans, file scans through the system picker, and local threat definitions do not require broad shared-storage access.

Google Play's all-files policy asks apps that do not require this permission to remove it. Policy: https://support.google.com/googleplay/android-developer/answer/10467955

## In-app disclosure and consent sequence

1. Before scanning installed apps, show the prominent local scan-access disclosure; the acknowledgement explicitly explains why the app reads installed-app inventory, what is kept locally, and that no package inventory is sent to servers.
2. Before enabling Downloads Sentinel, explain that monitoring is optional, starts only after the user selects a folder in Android's document picker, scans supported APKs in the selected folder and bounded subfolder depth, and can be stopped/revoked.
3. Android's document picker is the consent mechanism for the scoped folder URI. Do not replace it with Settings deep-links for all-files access.
4. The optional `feed` flavor is separate: it requires an explicit in-app network-feed consent toggle and a configured Ed25519 public key before any request is accepted. The offline flavor does not declare INTERNET.

## Release gate

- Submit the accurate `QUERY_ALL_PACKAGES` declaration and prominent-disclosure description in Play Console and wait for review outcome.
- Inspect merged release manifests, including the default `offlineRelease` APK/AAB, to verify `MANAGE_EXTERNAL_STORAGE`, `READ_EXTERNAL_STORAGE`, and `INTERNET` are absent from the offline build.
- Test the SAF grant/revocation paths on Android 11+ and legacy supported APIs in the local emulator matrix.
