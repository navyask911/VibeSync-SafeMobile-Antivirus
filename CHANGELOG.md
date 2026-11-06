# SafeMobile Antivirus Changelog

## 1.6.2 — 2026-11-06

- Updated the scan document picker to accept all MIME types, including plain-text EICAR test files.
- Fixed Pro paywall close and system-back behavior to pop to the previously opened screen instead of always returning Home.
- Made the Pro paywall vertically scrollable and allowed shared toolbar titles/subtitles to wrap at larger font scales.
- Added a regression test for the Settings Download/Folder Monitoring switch callback at 2× font scale.

## 1.6.1 — 2026-11-06

- Added the new legacy, round and adaptive launcher icon assets for all Android density buckets.
- Added the refreshed Android splash screen branding and AndroidX SplashScreen integration.
- Fixed theme-selector text truncation at larger system font scales by reflowing the selector into readable full-width options.
- Added back navigation to Settings sub-pages while retaining the shared back control for routed Tools details and Scan Results.
- Added an expandable inline Crown subscription offer with a direct route to the existing Pro subscription screen.
- Updated full-screen Pixel 6 Paparazzi coverage for 1.0×, 1.5× and 2.0× font scales.

## 1.6.0

- Offline-first scanning engines, YARA/ML integration and subscription/ads gating.
- Full-screen Compose navigation and visual regression coverage.
