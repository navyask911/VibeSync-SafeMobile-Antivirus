# Paparazzi UI snapshot tests

SafeMobile keeps committed full-screen Pixel 6 Paparazzi baselines for Home, Protection Tools, Scan Results, and Settings. The UI regression suite captures Home, Protection Tools, and Settings at font scales 1.0x, 1.5x, and 2.0x. Compose semantics tests separately verify text bounds at 320dp and 2.0x font scale.

## Verify snapshots

Run the offline debug unit tests and compare the rendered UI against the committed baselines:

```bash
./gradlew --no-daemon testOfflineDebugUnitTest verifyPaparazziDebug
./gradlew --no-daemon connectedOfflineDebugAndroidTest
```

The connected task runs on the Android emulator CI job. Compose semantics tests verify theme selection, monitoring switches, dashboard actions, destinations, accessible icons, and text bounds in a 320dp viewport at 2.0x font scale. Host-side MockWebServer fixtures only permit loopback traffic, so test requests cannot contact public threat-feed or Cloudflare endpoints.

A verification failure means a rendered screen differs from its baseline or a baseline is missing. Review the Paparazzi HTML report under `app/build/reports/paparazzi/offlineDebug/` before changing any images.

## Record intentional UI changes

To regenerate the baselines after an approved UI change:

```bash
./gradlew --no-daemon recordPaparazziDebug
```

Review the PNG changes and commit the complete `app/src/test/snapshots/` directory with the related UI change. Do not delete baselines or update them merely to silence a failing test. The recording workflow commits the nine Pixel 6 full-screen stress baselines for Home, Protection Tools, and Settings at 1.0x, 1.5x, and 2.0x font scale. It rebases the generated images onto the latest target branch before pushing so concurrent CI metadata commits cannot discard the snapshots.

## Coverage

- Home dashboard: Light, Midnight, and OLED
- Protection Tools: Light, Midnight, and OLED
- Scan Results: Light, Midnight, and OLED
- Settings panel: Light, Midnight, and OLED
- UI regression snapshots: Home, Protection Tools, and Settings on Pixel 6 at 1.0x, 1.5x, and 2.0x font scale
- Compose wiring: theme buttons, Security Alerts and Install Sentinel switches, Scan now, All tools, and protection-card routes
- Security score logic: direct pending-action deductions and 0–100 clamping
- Network isolation: MockWebServer hardcoded fixtures with external-host blocking

Snapshots are host-rendered regression tests. They do not replace the existing Android emulator, scanning-engine, billing, or AdMob test gates.
