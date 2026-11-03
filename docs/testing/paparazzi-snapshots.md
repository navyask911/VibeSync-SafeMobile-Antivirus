# Paparazzi UI snapshot tests

SafeMobile keeps committed Paparazzi baselines for the current dashboard, scan-results screen, and Settings panel. Each screen is captured in both Light and Midnight themes, for six PNG baselines in total.

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

- Security dashboard: Light and Midnight
- Scan-results screen: Light and Midnight
- Settings panel: Light and Midnight

Snapshots are host-rendered regression tests. They do not replace the existing Android emulator, scanning-engine, billing, or AdMob test gates.
