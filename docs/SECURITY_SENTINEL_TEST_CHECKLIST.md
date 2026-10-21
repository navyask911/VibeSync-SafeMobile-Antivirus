# SafeMobile Download Sentinel and uninstall manual test checklist

These checks complement CI, unit tests, lint, and the Room DAO instrumentation test. Use only a harmless test APK you own; never use live malware.

## Download Sentinel and WhatsApp sharing
1. Enable **Download Sentinel** in SafeMobile. Grant shared-storage/all-files access if requested and notification permission on Android 13+.
2. Download or share a harmless APK from WhatsApp into public Downloads and leave the service running. Verify that a new/modified APK is observed by the Downloads watcher or MediaStore observer, its streamed hashes are checked against the local threat database, and a local Room incident entry is recorded.
3. Use a test-only local threat hash to simulate a confirmed match. Verify SafeMobile creates an encrypted Quarantine Vault copy, records the hash/reason/status, and posts a malicious-download notification. If Android refuses source deletion, the original must be retained and the notice must not claim the source was removed.
4. In non-strict mode, test an unknown APK/EXE: notify/review without silently deleting/moving the source. In strict mode, verify it is moved to the encrypted vault where Android access permits; restore it using the existing Quarantine UI.
5. Revoke storage permission, deny notifications, stop the process, and reboot. Status should reflect the foreground service and permissions. Service starts at boot only when explicitly enabled and privacy is acknowledged; OS/OEM restrictions must not crash the app.
6. Open the APK after download and confirm Android's installer remains in control. **Download Sentinel does not reliably interrupt or block APK installer prompts.** Post-install package checks remain best-effort.
7. Repeat on Android 10, 11, 13 and 14+ and at least one OEM, recording device/OS and outcomes without accessibility dumps or personal data.

## Scanned Apps uninstall flow
1. Mark a test user-installed app as suspicious using test-only definitions; tap **Uninstall** and confirm Android's normal user-confirmation dialog appears.
2. Confirm uninstall and verify the package refresh removes it from the list. Repeat and cancel to confirm the app remains installed.
3. Tap the action for a system app or active device-admin package; verify uninstall is blocked and **App Info** is offered instead.
4. Run the instrumented fallback test for a missing ACTION_DELETE handler and verify Settings App Info opens. Test a missing package and restricted OEM behavior without crashing.

## Platform and Play policy caveats
Android controls package installation. File observation is best-effort and depends on storage access and background-service availability. `MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, and the `specialUse` foreground-service subtype remain subject to Google Play policy and review. Do not market the feature as a universal installer blocker.
