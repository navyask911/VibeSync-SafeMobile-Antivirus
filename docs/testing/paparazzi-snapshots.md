# Paparazzi UI snapshot tests

SafeMobile keeps committed Paparazzi baselines for Home, Protection Tools, Scan Results, and Settings. Each screen is captured in Light, Midnight, and OLED themes.

## Verify snapshots

Run the offline debug unit tests and compare the rendered UI against the committed baselines:

```bash
./gradlew --no-daemon testOfflineDebugUnitTest verifyPaparazziDebug
```

A verification failure means a rendered screen differs from its baseline or a baseline is missing. Review the Paparazzi HTML report under `app/build/reports/paparazzi/offlineDebug/` before changing any images.

## Record intentional UI changes

To regenerate the baselines after an approved UI change:

```bash
./gradlew --no-daemon recordPaparazziDebug
```

Review the PNG changes and commit the complete `app/src/test/snapshots/` directory with the related UI change. Do not delete baselines or update them merely to silence a failing test. The feature-branch recording workflow performs the same recording step and commits generated PNGs to the branch.

## Coverage

- Home dashboard: Light, Midnight, and OLED
- Protection Tools: Light, Midnight, and OLED
- Scan Results: Light, Midnight, and OLED
- Settings panel: Light, Midnight, and OLED

Snapshots are host-rendered regression tests. They do not replace the existing Android emulator, scanning-engine, billing, or AdMob test gates.
