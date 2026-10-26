# Incident response regression checks (1.0.7)

Security Alerts and Voice Alerts remain separate, opt-in settings. Enabling Security Alerts
now discloses a five-second siren at maximum alarm volume for exact malware matches. The
previous alarm volume is restored afterward unless the user changed it during playback.
DND, fixed-volume policies, missing voice packs and denied permissions must never crash the app.

## Valid harmless fixture

Use the matched APK/JSON pair produced by `scripts/test_siren.sh`, as described in
[the fixture guide](SIREN_AND_FOLDER_TESTING.md). Do not use an EICAR text file renamed to APK.
These fixtures do not modify the production signed database or contain actual malware.

1. Import the fixture JSON on a test device. Enable Security Alerts and optionally Voice Alerts.
   Keep the fixture outside monitored folders (or temporarily stop Sentinel) for an **installed-app** test.
2. On Android 14+, optionally grant full-screen access from Settings > Security Alerts >
   Full-screen incident alerts. Declining must leave the dashboard and notification path usable.
   Android/Google Play restrict automatic grants to calling/alarm use cases: do not claim this
   antivirus is automatically eligible. Locked devices may show the incident Activity when allowed;
   unlocked devices may show heads-up UI instead. No direct background Activity launch is attempted.
3. Install the harmless fixture APK while SafeMobile is in the background. Confirm an urgent
   notification, a five-second siren, and the fixture's name/icon on the incident screen.
4. Tap Dismiss during playback: audio must stop immediately and stay stopped. Install/update the
   same fixture again: a fresh scan and alert must occur. Also test uninstalling/reinstalling it.
5. Tap UNINSTALL NOW. Only Android's confirmation UI should open; cancelling must leave the
   app installed. No background PackageInstaller removal or device-owner hiding is permitted.
6. Open SafeMobile from its launcher during playback: stop/release audio and cancel the timer.
   Trigger another incident and leave it alone: the alarm must stop automatically after 5 seconds.
7. Set the system language to Kannada, with an installed offline Kannada TTS voice. Confirm
   Kannada speech. Installed apps must be described as detected after installation and needing
   review/removal; only files actually copied into quarantine may be described as quarantined.
8. Deny notifications, disable full-screen access, and remove the TTS voice pack in separate tests.
   The app must remain usable. Full-screen access is optional; no permission loops are allowed.

The notification channel intentionally has no sound of its own: MediaPlayer owns the stoppable
STREAM_ALARM siren, avoiding a second channel sound that would continue after cancellation.
High importance, content and dismissal actions remain available when Android permits notifications.
Handler timing is a 5,000 ms scheduled stop, subject to normal Android scheduling/process limits.

## Add any TTS language

Installed-app warnings use `R.string.voice_alert_malware_detected`, with the English fallback
in `app/src/main/res/values/strings.xml`. The engine calls
`textToSpeech.setLanguage(Locale.getDefault())`; warning text is loaded with `context.getString(...)`
from resources configured for that same system locale at speech time. No English warning is
hardcoded in the speech engine. Quarantined-file and review warnings retain separate resource
keys, so installed apps are never falsely described as already quarantined.

Translations for all 22 currently supported app languages are included, including Hindi,
Kannada and Spanish. To add another global language, add a translated entry with the same
key to the appropriate resource file and rebuild the app, for example:

- `app/src/main/res/values-hi/strings.xml` — Hindi (already included)
- `app/src/main/res/values-kn/strings.xml` — Kannada (already included)
- `app/src/main/res/values-es/strings.xml` — Spanish (already included)
- `app/src/main/res/values-sw/strings.xml` — Swahili (example additional language)

```xml
<resources>
    <string name="voice_alert_malware_detected">Onyo. Programu hasidi imegunduliwa baada ya kusakinishwa. Ikague au uiondoe sasa.</string>
</resources>
```

Also translate `voice_malicious_quarantined`, `voice_suspicious_quarantined`, and `voice_app_review`.
The repository's localization guard requires each supported `strings.xml` to cover all
translatable fallback keys; copy and translate the existing fallback file when adding a new locale.
Android automatically selects matching resources after the phone language changes. The owner
must also install/enable that language's TTS voice pack in Android settings. TTS speaks the supplied
translated text; the voice pack does not translate English. An untranslated resource falls back
to English, and a missing/unsupported voice pack is logged without crashing or blocking the app.

## Quarantine and appearance

- Delete an ordinary quarantined fixture; confirm its encrypted file and Room index are removed.
- Remove a fixture externally before confirming deletion; expect “File could not be deleted”.
- Simulate a denied/locked file and a storage failure; retain the Room row and show the same
  feedback. All file operations run on IO; Room row deletion uses a transaction only after the
  payload deletion succeeds. Filesystem operations and Room cannot share one ACID transaction.
- With both Android light and dark modes, visit Dashboard, Scan, Quarantine and Settings.
  Expect background #0F172A, surface #1E293B, cyan #06B6D4, rounded 16 dp bordered cards,
  and light system-bar icons. Previously saved light-theme preferences must have no effect.
- Confirm the existing six-hour GitHub-only, signature-verified definition sync still works.

Inspect `adb logcat -s SafeMobileScan SafeMobileSiren SafeMobileSecurityAlert SafeMobileVoiceAlert`
for a fresh package event and final scan result on each installation. Emulators cannot verify
speaker loudness, OEM DND behavior, or the quality of installed TTS voices; check those on-device.
