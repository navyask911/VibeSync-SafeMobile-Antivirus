# SafeMobile 1.0.10 device testing

## Manual siren diagnostic (not a malware detection)

In **Settings > Siren diagnostics**, tap **Test Threat Siren**. This user-triggered
five-second alarm calls the production `SecurityAlertNotifier` and opens a clearly
labeled `ThreatDetectedActivity` preview. It does NOT create an incident record,
modify hash/signature definitions, flag any installed app or offer an uninstall action.
Tap **Dismiss** to stop the test. Check `adb logcat -s SafeMobileSiren SafeMobileSecurityAlert SafeMobileScan`
if playback is inaudible. Android notification permission, alarm volume, DND and
Oppo/ColorOS audio policies may independently affect delivery.

The test proves **local playback/UI only**, not successful post-install detection.
The harmless `SafeMobile-Siren-Test.apk` requires importing the exact matching
`siren-test-definitions.json` from the SAME release before installation. If the
definitions are absent or a different APK build is installed, no verified local
hash match exists and the app must not falsely sound the real-threat siren.

**Android 8+ limitation:** A manifest-registered implicit PACKAGE_ADDED receiver
cannot guarantee background delivery. The runtime receiver observes installs while
SafeMobile's process is alive. No app-level battery setting can guarantee delivery
after a user/OEM force-stop. Use the Dashboard's battery settings advisory and
enable notifications where available. Android 14+ full-screen access is optional;
when ungranted, a high-priority notification is the fallback. The automatic siren
still requires an exact verified hash match and the user's Security Alerts opt-in.

## Valid, harmless siren fixture

Run `bash scripts/test_siren.sh` on a machine with JDK 17 and Android SDK platform 36/build-tools. It generates a signed, installable APK with a binary Android manifest and no executable code, components, network access or permissions. `apksigner` and `aapt2` verify it before the script writes its exact SHA-256 to `siren-test-definitions.json`.

The release also attaches the APK and its matching JSON for phone-only testing. Download the matching pair from the same release. This is an explicitly imported local test indicator, not a change to the signed production database or its trust root.

1. In SafeMobile, finish the privacy disclosure, enable **Settings > Security Alerts**, and allow Android notifications. Optionally enable Voice Alerts for TTS. Check the channel's alarm sound and volume in Android settings; Android still controls DND and audio routing.
2. Open **Scan > Import definitions** and select `siren-test-definitions.json`. Accept the unverified local-file disclosure only for this fixture you generated or obtained from this repository's release.
3. Enable Download Sentinel and grant a specific folder. Import the JSON before copying the test APK into the monitored folder, so an earlier clean scan cannot consume the test event.
4. Copy `SafeMobile-Siren-Test.apk` into that folder. The exact hash should match, an encrypted quarantine copy should be written, and a high-importance notification/siren should fire. With a read-only folder grant Android may retain the source; inspect the incident action.
5. For **post-install** receiver testing, temporarily stop Download Sentinel or keep the fixture outside monitored folders, then install the harmless fixture after importing its hash. This prevents file quarantine from removing the APK before Android can install it. It has no launch icon because it contains no activity. The installed-app alert asks for review/uninstall; it does not claim Android has isolated an installed package.
6. Inspect `adb logcat -s SafeMobileScan SafeMobileSentinel SafeMobileSecurityAlert`. Remove the test app using `adb uninstall com.safemobile.sirentest`, and remove test files when done. The imported indicator matches only this exact harmless APK.

A freshly generated fixture uses a new disposable signing key and therefore a new hash. Always import its matching JSON. Uninstall an older fixture before installing a newly generated one if Android reports a signing mismatch. No genuine malware sample is needed.

## Folder selection and limited coverage

On Android 11+, SAF prohibits the storage root and the top-level Download directory. Changing intent flags cannot override this. The picker opens at Download as a hint; choose a browser-download subfolder and configure the browser to save APKs there, or scan an individual file. On versions/providers that grant the whole Download directory, SafeMobile accepts it.

WhatsApp Documents is commonly `Android/media/com.whatsapp/WhatsApp/Media/WhatsApp Documents`; paths vary by WhatsApp edition/device. Select it in the picker. Any other granted folder is saved and monitored, without a forced retry loop. The screen lists the exact selected folder; selecting a custom location does not falsely mark the expected Download/WhatsApp location as covered.

Multiple URI grants persist across reboot. Each accessible tree is traversed recursively. Revoking one grant does not stop scans of the other folders. Android may stop foreground work or impose provider restrictions; the dashboard's yellow limited-protection banner remains whenever expected folder coverage or monitoring is missing. Skip/cancel always returns to the dashboard.

## Score and scan results

The configuration score starts at 100 and deducts 20 for reported-disabled Play Protect, 10 for missing/older-than-24h signed release definitions, 20 for enabled non-system accessibility apps, and 20 for active non-system device admins. The last two deductions apply once per category. Legitimate assistive/admin apps can lower the score; review their purpose before changing settings.

Play Protect's authenticated verdict requires Play Integrity/Play Console/backend integration. This offline build explicitly labels the status unverified or user-reported; reporting it after checking Google Play expires after 24h. Unknown signals never imply an all-clear. The database age uses the publication time of a successfully signature-verified GitHub release, not the time an old bundle was redownloaded.

Scan completion counts remain visible after navigation/relaunch. Unreadable files and heuristic review signals remain separate from confirmed signature matches. No scan result or score guarantees that a device is malware-free.
