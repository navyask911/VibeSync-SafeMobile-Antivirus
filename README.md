<div align="center">

# 🛡️ SafeMobile Antivirus

### Local-first Android security. Your scans stay on your device.

**APK inspection · Signed threat definitions · DEX rules · Device posture · Incident response · 51 locale resource folders**

[![Android](https://img.shields.io/badge/Android-API%2026%E2%80%9336-3DDC84?logo=android)](https://developer.android.com/)
[![Kotlin](https://img.shields.io/badge/Kotlin-Jetpack%20Compose-7F52FF?logo=kotlin)](https://kotlinlang.org/)
[![Privacy](https://img.shields.io/badge/Scanning-100%25%20on%20device-1FA67A)](docs/PRIVACY_POLICY.md)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue)](LICENSE)

**v1.0.18 · versionCode 20261111 · Android 8.0+ · package `com.vibesync.antivirus`**

[Verified signed AAB](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/releases/tag/safemobile-v1.0.18-code20261111-run12) · [Privacy policy](docs/PRIVACY_POLICY.md) · [Report issues](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues)

</div>

---

## Privacy-first by design

**100% offline scanning. Zero scan telemetry. No cloud malware scanning.** SafeMobile performs readable APK and file inspection, hash matching, DEX signature checks and device posture review locally. It does not upload APK bytes, file hashes, scan verdicts, scan history, permission snapshots or Android-ID-derived Pro bindings to a developer server. Room stores scan history on device; sensitive stored data uses Android Keystore-backed encryption where described in the [privacy policy](docs/PRIVACY_POLICY.md).

**Important distinction:** offline scanning does not mean the entire app never uses the internet. The app needs connectivity for **optional cryptographically verified threat-intelligence updates**, **optional research model downloads**, and **user-initiated Google Play Billing**. These services can expose ordinary request metadata (such as IP addresses) to GitHub, network intermediaries or Google according to their own policies. Core scanning remains usable without connectivity using already available local indicators.

## Security capabilities

| Layer | What v1.0.18 actually does |
|---|---|
| 🔎 **Local hash intelligence** | Computes file digests on device and compares with approved local indicators. SHA-256-only MalwareBazaar-derived database releases are prepared approximately every **6 hours by GitHub Actions**, subject to authorization, API availability and successful signing. The phone checks for signed releases and validates their Ed25519 signature before use; updates are not guaranteed every six hours. No malware samples ship in the AAB. |
| 🧬 **DEX/YARA-compatible rules** | Inspects APK DEX content with a **bounded Kotlin YARA-compatible literal/Boolean subset**, including adapted MIT-attributed rules. **Not** the full native libyara engine; findings are advisory, not conclusive malware verdicts. |
| 🧠 **On-device Drebin ML** | Packages an **18,584-byte, SHA-256-pinned trained research TensorFlow Lite model with exactly 215 static features**, with APK feature extraction done locally. **Not activated for production malware classification**: `validated=false` and `production_ready=false`. Only a separately gated research benchmark may score the candidate; the published research holdout is not a claim about live malware detection. |
| 🕵️ **Install and sideload review** | Monitors supported new-package events, flags risky permissions and installation sources and allows inspection of evidence before making a decision. Android and OEM restrictions may limit delivery. |
| 🛡️ **Device Posture audit** | Reviews visible **Accessibility services, Device Administrators, notification listeners and overlay capabilities**, and provides Android settings routes. Elevated privilege is not itself proof of malware. |
| 🧊 **Local quarantine** | Supports encrypted app-private quarantine where available, guided restoration and user-controlled removal. No automatic deletion of user files. |

### Incident response

A detected security incident may trigger a **five-second alarm-stream siren**, an Android notification and an optional **full-screen alert** with a user-directed uninstall action. Audio routing, volume, notification delivery, full-screen intent eligibility and uninstall confirmation remain controlled by Android and the device manufacturer. SafeMobile **does not silently uninstall apps or override Android permissions**.

### Accessible and adaptable

- **51 bundled locale folders** with format/placeholder completeness checks in CI. Localization resources span scripts including Kannada, Hindi, Tamil, Telugu, Japanese, Arabic and others; device-specific translation quality and layouts still need human QA.
- **Three interface themes:** Midnight, Light and OLED, using Jetpack Compose Material 3.
- Screen-reader descriptions, scalable typography and locally rendered analytics; actual accessibility varies by Android version and configuration.

## SafeMobile Pro

**Optional, not required for core protection.** `safemobile_pro_1_year` is a Google Play Billing **consumable**, not a recurring subscription. The intended **India list price is ₹299 per one-year pass**, but the authoritative local price, taxes, currency and availability are **whatever Google Play displays at checkout**. Do not advertise ₹299 as a guaranteed global price without confirming the active Play Console configuration.

Approved purchases credit **365-day device-local entitlements**, and multiple purchased quantities can extend the local expiry. The SHA-256 hash of an app-scoped Android ID ties the entitlement to the current Android installation. Sensitive entitlement details are stored in Keystore-protected encrypted preferences. Google Play processes payments; SafeMobile does not store card numbers, bank details or raw purchase tokens as a persistent record.

**Important:** consumed Pro passes cannot be restored after uninstalling, clearing app data, device reset or encryption-key loss. No cloud entitlement sync or account recovery is provided. The paywall explains this before purchase. Pro changes optional **research model download cadence** (weekly by default; daily for Pro), **not** live malware-classification capabilities.

## Transparent automated research

- [Signed hash update workflow](.github/workflows/update-malware-db.yml) is scheduled **every six hours**. It can optionally extract a limited batch of static research features and send them to the separate [MLOps repository](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware), with credentials and API access supplied by the owner.
- Receiving a batch **does not guarantee successful retraining or promotion every six hours**. Trained candidates must meet upstream evaluation gates and separately pass Android/modern-sample validation; a published research candidate is not active production protection.
- [200-APK pilot](docs/BENCHMARK_REPORT.md): **NOT MEASURED** as of 31 October 2026. GitHub run [#1](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41171013990) failed on Android external-files access (`EACCES` opening `batch.json`) before report publication. There are **no verified TPR, FPR or scan-latency figures**. No independent certification or universal detection claim is made.

## Build and verify

```bash
# Java 17 and Android SDK 36
./gradlew --no-daemon testOfflineDebugUnitTest lintOfflineDebug
./gradlew --no-daemon assembleOfflineDebug

# Release signing needs KEYSTORE_BASE64, KEYSTORE_PASSWORD,
# KEY_ALIAS and KEY_PASSWORD from private CI secrets.
./gradlew --no-daemon bundleOfflineRelease
```

Build-time staging verifies the research model size and SHA-256 against an immutable GitHub Release. For the trusted hash feed, configure the signing trust root. The product has separate `offline` and opt-in `feed` flavors; the `offline` flavor still requires the INTERNET permission for signed updates and Google Play purchases.

## Real-world limitations and responsible disclosure

SafeMobile does not have kernel privileges, cannot inspect all apps and private files on every Android device, cannot guarantee installation-interception or full-screen prompts, and cannot guarantee detection of unknown threats. User-trusted apps are intentionally excluded from applicable checks. Limited YARA patterns can produce false positives. Do not describe the experimental 215-feature model as active protection. Before claiming performance publicly, publish independently verified TPR/FPR and sample provenance.

For permissions and Play review, see [privacy policy](docs/PRIVACY_POLICY.md), [Play permissions](docs/PLAY_PERMISSIONS.md), [ML research gates](docs/ML_MODEL_ACTIVATION.md), [detection coverage](docs/DETECTION_COVERAGE.md) and [benchmark methodology](docs/INDUSTRY_BENCHMARK_SETUP.md).

## License, attribution and contact

Project-owned source is under **Apache License 2.0**: [LICENSE](LICENSE). Third parties retain their own licences. See [NOTICE](NOTICE), [third-party inventory](docs/THIRD_PARTY_LICENSES.md), [generated dependency notices](THIRD_PARTY_NOTICES.md) and [CycloneDX SBOM](docs/sbom.json). TensorFlow Lite is Apache-2.0; the bundled rule subset includes MIT-licensed third-party adaptations; **native libyara is not included**. Data/model attribution is documented separately.

**Developer:** Navyask911 / VibeSync. Contact for privacy, responsible security disclosure and accessibility issues: [GitHub Issues](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues). Do not attach malware samples or sensitive personal data to a public issue.

---

<div align="center"><strong>SafeMobile — private-by-design scanning, with transparent limits.</strong></div>
