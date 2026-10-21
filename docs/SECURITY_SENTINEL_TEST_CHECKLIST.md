# SafeMobile Sentinel and uninstall manual test checklist

These checks complement automated build, lint, JVM tests, and the Room DAO instrumentation test. Use a benign test APK that you own; do not use live malware.

## Accessibility Guard / WhatsApp share flow
1. Install a harmless test APK, enable Download Sentinel & Interceptor in SafeMobile, and use the setup button to enable **SafeMobile Accessibility Guard** in Android Accessibility settings.
2. Grant all-files access where the OS requests it, and grant notification permission on Android 13+.
3. Share the harmless APK from WhatsApp to Downloads, then open it. Confirm that SafeMobile inspects only the package-installer window, attempts Cancel/BACK, records a local incident row, and shows the interruption notice/notification. This verifies the best-effort mechanism, not malware detection or a universal install block.
4. Repeat with the feature disabled and with a non-APK installer prompt. Non-APK prompt should not be interrupted by the detector.
5. Put a known test hash into the local test definitions and create an APK with that exact hash; confirm the encrypted Quarantine Vault entry is recorded. Test a new, unknown APK in non-strict mode (notify/review; do not remove it), then enable strict mode and verify that the unknown file is moved to the encrypted vault when Android permits it.
6. Deny notification permission, revoke storage access, disable the accessibility service from system Settings, stop the app process, and reboot. Verify the Settings status reports the actual service/permission state, observer startup occurs only when opted in and permitted, and denied operations do not crash. Restore a quarantined sample through the existing Quarantine UI.
7. Repeat on Android 10, 11, 13, and 14+ plus at least one OEM installer. Record device, OS, installer package, and result; do not record arbitrary accessibility text or PII.

## Scanned Apps uninstall flow
1. Scan a known user-installed test app marked suspicious using test definitions; tap Uninstall and confirm Android's normal uninstall prompt appears.
2. Confirm uninstall and verify the package disappears from the scan list after the result/resume refresh. Repeat and cancel to ensure the app remains listed.
3. Test a system app and an active device-admin app; verify no uninstaller is launched and only **App Info** is offered.
4. Simulate a missing ACTION_DELETE handler in the instrumented test; verify fallback to `Settings.ACTION_APPLICATION_DETAILS_SETTINGS`. Test package-not-found and restricted OEM behavior without crashes.

## Release/policy caveats
Accessibility is optional, user-enabled, and limited by Android/OEM behavior. Do not advertise guaranteed interception. `MANAGE_EXTERNAL_STORAGE`, package visibility, accessibility use, and the `specialUse` foreground-service subtype remain subject to Google Play policy and review.
