# SafeMobile Antivirus Changelog

## 1.7.4

- Declares the user-granted Android overlay special-access permission so SafeMobile is listed in the system's “Display over other apps” screen; the existing setup action opens Settings and refreshes the grant state when the app resumes.
- Fixes Device Administrator activation when Compose supplies a wrapped context by launching Android's explicit confirmation screen with the registered SafeMobile admin component.
- Adds an instrumentation check for the overlay permission declaration and Device Admin receiver metadata.


- Aligns Shield, Scan & Lab, Tools Hub and Console with the supplied HTML prototype using scalable Material vector iconography.
- Standardizes larger icon badges across protection tiles, scan modes/results/detection layers, Tools Hub cards, Console sections and the setup checklist.
- Adds accessible content descriptions for the four primary navigation icons; vectors remain sharp across display densities and font scales.

## 1.6.5 — 2026-11-06

- Log donation worker startup, WorkManager queue persistence results, and selected-document staging failures so skipped uploads can be distinguished from HTTP failures.
- Route install-alert donations through the same network-constrained WorkManager path as manual file scans; closing the alert Activity cannot cancel approved delivery.
- Keep the Cloudflare payload privacy-minimal: verified SHA-256 and confirmed THREAT verdict, with an optional validated 215-feature APK vector.

## 1.6.4 — 2026-11-06

- Move per-sample Global Threat Intelligence donations to a network-constrained WorkManager worker so delivery survives screen dismissal and process recreation.
- Persist picker URI read grants for deferred contribution work and retry transient network/server failures.
- Send contributions to the explicit Cloudflare `/donate` route with SHA-256 and confirmed `THREAT` verdict; include the 215-bit Drebin vector only when a valid APK vector exists.
- Add URL, HTTP status and exception Logcat diagnostics while retaining the no-package-name/no-device-identifier payload boundary.

## 1.6.3 — 2026-11-06

- Wired completed manual scans to a dedicated confirmed-threat siren event, including picked-file scans.
- Play the local five-second alarm for a confirmed manual-scan threat even when notification or full-screen alert preferences are off.
- Keep voice narration opt-in; initialize TTS asynchronously and log unavailable voice-pack or engine failures.
- Added regression coverage for manual-versus-automatic confirmed-threat alert policy.

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
