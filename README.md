<p align="center">
  <img src="docs/assets/safemobile-shield.svg" alt="SafeMobile Antivirus shield logo" width="116" height="116">
</p>

<h1 align="center">SafeMobile Antivirus</h1>

<p align="center">
  <strong>Cybersecurity that stays on your device.</strong><br>
  <em>On-device Malware Scanning. Ad-supported Free Tier. No AdMob Ads with Pro.</em>
</p>

<p align="center">
  <a href="https://developer.android.com/about/versions/oreo"><img src="https://img.shields.io/badge/Android-8.0%2B-3DDC84?logo=android&amp;logoColor=white" alt="Android 8.0+"></a>
  <a href="https://kotlinlang.org/"><img src="https://img.shields.io/badge/Language-Kotlin-7F52FF?logo=kotlin&amp;logoColor=white" alt="Kotlin"></a>
  <a href="https://developer.android.com/compose"><img src="https://img.shields.io/badge/UI-Jetpack%20Compose-4285F4?logo=jetpackcompose&amp;logoColor=white" alt="Jetpack Compose"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-2563EB" alt="Apache 2.0 License"></a>
  <a href="docs/PRIVACY_POLICY.md"><img src="https://img.shields.io/badge/Privacy-100%25%20Offline%20Core-078B79?logo=shield&amp;logoColor=white" alt="Privacy: 100% offline core scanning"></a>
  <a href=".github/workflows/android-ci.yml"><img src="https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/workflows/android-ci.yml/badge.svg" alt="Android CI"></a>
</p>

<p align="center">
  <strong>Android 8.0+ · Kotlin · Jetpack Compose · Privacy-first security</strong><br>
  <a href="docs/PRIVACY_POLICY.md">Privacy</a> ·
  <a href="docs/BENCHMARK_REPORT.md">Measured results</a> ·
  <a href="docs/ANNUAL_BENCHMARK_RESULTS.md">Annual benchmarks</a> ·
  <a href="https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues">Report a problem</a>
</p>

---

## Why SafeMobile?

**Powerful security should not come at the price of your privacy.**

Some mobile security tools depend on remote lookups, user accounts or analytics. SafeMobile takes a different approach: **inspect accessible files and apps locally, retain scan history on the device, and keep core protection working without an internet connection.**

SafeMobile keeps core malware scanning on the device and does not send scanned APK contents, scan verdicts or device-posture snapshots to a developer-operated server. The Free tier is ad-supported by Google AdMob. Google's Mobile Ads Next-Gen SDK automatically collects and shares IP address; user product interactions (including app launches, taps and video views); diagnostic information (including app launch time, hang rate and energy usage); and device/account identifiers (including Android Advertising ID, App Set ID and, where applicable, identifiers associated with signed-in accounts) for advertising, analytics and fraud prevention. Google states that this data is encrypted in transit using TLS. While SafeMobile Pro is active, the app does not initialize AdMob or make ad requests; Pro disables AdMob advertising and its SDK data collection. The app does not send scanned APK contents, scan verdicts or local scan history to AdMob. See the [privacy policy](docs/PRIVACY_POLICY.md) for details.

> **Offline-first, not network-free:** optional signed threat-intelligence updates, optional research model downloads and user-initiated Google Play Billing use network services. Their providers can receive ordinary request/IP metadata. None is required for core offline scanning. [Read the privacy policy](docs/PRIVACY_POLICY.md).

## Security Capabilities

- 🛡️ **Multi-Engine Inspection — defense in depth.** **Local SHA-256 threat indicators** and **DEX static analysis** using a bounded Kotlin YARA-compatible rule subset. The signed hash database pipeline is scheduled about **every 6 hours**; actual releases depend on API access, validation and signing. A **215-feature TensorFlow Lite Drebin research model** is bundled, but **not active for production malware verdicts**. Its historical **97.45% Drebin holdout accuracy** is a research result, *not* SafeMobile's measured detection rate. [ML activation gates](docs/ML_MODEL_ACTIVATION.md).
- 🚨 **Incident Response — alert fast, act deliberately.** A **five-second alarm-stream siren**, security notification, **eligible full-screen alert**, and **user-confirmed uninstall prompt** can accompany detected incidents. Android and OEM restrictions govern audio, alert delivery and uninstall permissions; there is no forced takeover or silent removal.
- 🔍 **Device Posture Audit — visibility into risky privileges.** Inspect available **Accessibility services, Device Administrators, notification listeners and overlay permissions**, with installation-source and permission-risk signals. These are advisory indicators, **not proof of spyware**.
- 🌍 **Global & Accessible — designed for more users.** **51 bundled locale resource folders**, **Midnight / Light / OLED** themes, Material 3 Compose screens, adaptable typography and screen-reader support. CI checks resource completeness; individual translations and screen layouts still require human review.
- 🌐 **Global Threat Intelligence — optional and data-minimised.** OFF by default; requires both a Settings opt-in and a separate Donate tap for each confirmed malicious APK. The Android client sends only the detected malware SHA-256 hash and 215 binary behavioral features to the VibeSync Cloudflare Worker. It never uploads APK bytes, file paths, package names, scan history or device identifiers, and contains no GitHub token. Network providers may still process ordinary connection metadata.
- 🤖 **Research MLOps — improvement with validation gates.** GitHub Actions can extract limited static research features from available MalwareBazaar samples and dispatch them to the separate [ML research repository](https://github.com/navyask911/safemobile-Antivirus-Trained-ML-Data-of-Android-malware). **Retraining and deployment are conditional**, not automatic promises; research candidates do not become active production classifiers without independent validation.
- 📢 **Ad-supported Free tier.** Google AdMob provides Home dashboard banners and eligible interstitials after manual scans that find no confirmed threats, once UMP consent permits ad requests. The Next-Gen SDK automatically collects and shares IP address, product interactions, diagnostics and device/account identifiers (including Advertising ID and App Set ID) for advertising, analytics and fraud prevention. Active Pro users are excluded from AdMob initialization, requests and display.
- 💎 **SafeMobile Pro — optional, ad-free and device-bound.** An active Pro entitlement disables the AdMob SDK and all ad requests/displays. The **365-day local entitlement** has an **intended ₹299 India list price**, subject to the actual Google Play checkout price. No developer cloud entitlement account or backup; a consumed pass **cannot be restored** after uninstall, clearing app data or loss of local keys. Pro changes optional research-model update cadence, **not** the active detection engine.
- 🧊 **Private Quarantine — your files, your decision.** App-private encrypted quarantine where supported, guided restore and user-controlled removal. No automatic deletion of personal files.

### Engineering architecture

| Security layer | Available capability | Important limitation |
|---|---|---|
| **On-device detection** | Local hash matching, limited DEX/YARA-compatible signatures, accessible APK inspection | No kernel privilege or guaranteed coverage of every installed app |
| **Signed intelligence** | Optional cryptographically verified hash-definition updates | Online retrieval is optional and fresh updates are not guaranteed |
| **ML research** | SHA-pinned, 215-feature TFLite trained candidate | `validated=false` and `production_ready=false`: no production ML classifications |
| **Privacy & persistence** | Local scan history, Room/DataStore and Keystore-backed sensitive records | Third-party update/billing requests expose normal connection metadata |
| **Incident handling** | Siren, notification, user-directed follow-up | Android controls full-screen eligibility, permissions and uninstall confirmation |

## Security Validation & Annual Benchmarking

**Live intelligence:** View our Live Threat Intelligence Dashboard in real-time: [Link](https://navyask911.github.io/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/). This public research website is separate from the app; core scanning stays offline.

**Evidence before advertising performance.** The benchmark uses **200 real Android APKs**: **100 source-labeled malicious samples** and **100 F-Droid benign apps**. Ten Android emulator shards each process 10 malware-source and 10 benign APKs.

Its **Zero-Binary Repository** rule keeps raw malware samples outside the Git tree and GitHub artifacts. The test downloads samples to temporary CI runner scratch space, validates `PK\x03\x04` ZIP magic, compiled `AndroidManifest.xml` and SHA-256, then deletes the files. Password-protected archives use `pyzipper` with password `infected` when required. The sample APKs are inspected, **never installed or executed**.

**Industry Benchmark #11 — verified 31 October 2026** ([run](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/actions/runs/41224653496) · [generated report](docs/BENCHMARK_REPORT.md)):

| Actual measured metric | Result |
|---|---:|
| Scanned APKs | **200/200** (100 malicious-source, 100 benign) |
| Emulator shard health | **10/10 succeeded** |
| Confirmed-detection TPR | **0.0%** |
| Confirmed-detection FPR | **0.0%** |
| Advisory triage TPR / FPR | 12.0% / 8.0% |
| Average scan latency | **4,109.48 ms / APK** |
| Research ML samples scored | **0** |

**Interpretation:** The active scanner did not return confirmed detections for this particular malicious-source cohort. `SUSPICIOUS` is triage, not a confirmed threat. Labels originate from the corpus providers and are **not independently adjudicated ground truth**. This run is not third-party antivirus certification; the historic research-model holdout figure is not a substitute for these measurements. The [annual ledger](docs/ANNUAL_BENCHMARK_RESULTS.md) preserves its separately managed historical and sign-off records.

## SafeMobile Pro

**Core protection is not behind a paywall.** `safemobile_pro_1_year` is a Google Play Billing **consumable**, **not a recurring subscription**. Eligible purchases grant or extend locally stored 365-day Pro access. ₹299 is an intended India price, **not a guaranteed charge**; Google Play determines the price, currency and taxes shown at purchase.

**Read before buying:** There is no developer cloud entitlement recovery. Uninstalling, clearing app data, resetting the device or losing the encryption key can permanently prevent recovery of a consumed Pro pass.

## Google Play Store description

**On-device Malware Scanning. Ad-supported Free Tier. No AdMob Ads with Pro.**

SafeMobile performs its core malware scanning on your device. It checks readable installed APKs and files you select against local threat definitions and performs supported static inspection. A no-match result is not a guarantee that a file is safe.

**Free tier:** Supported by Google AdMob. Banner ads appear on the Home dashboard, and an interstitial may appear after a successful manual scan when no confirmed threats are found. Google may process the Advertising ID and IP address for ad delivery and fraud prevention. Google's UMP privacy choices are presented before ad requests where required.

**SafeMobile Pro:** While Pro is active, AdMob is not initialized and no ads are requested or displayed. Pro entitlement is verified locally on this device. Optional definition updates, Google Play purchases and any explicitly enabled Global Threat Intelligence contribution remain separately disclosed network features.

SafeMobile is not a kernel-level security product and cannot inspect every private file or guarantee detection of every malware family. Coverage depends on Android access, local definitions and device restrictions.

## Documentation

| Resource | Description |
|---|---|
| 🔒 [Privacy Policy](docs/PRIVACY_POLICY.md) | Local scan retention, AdMob disclosures, Pro advertising exemption and optional network use |
| 🏪 [Google Play Store description](docs/PLAY_STORE_DESCRIPTION.md) | Free-tier and Pro advertising disclosure |
| 📊 [Annual Benchmark Results](docs/ANNUAL_BENCHMARK_RESULTS.md) | Permanent ledger for rigorous **200-APK testing** |
| 🧪 [Current Benchmark Report](docs/BENCHMARK_REPORT.md) | Actual TPR, FPR and latency with provenance and caveats |
| 🧠 [Research Model Activation](docs/ML_MODEL_ACTIVATION.md) | 215-feature model, holdout context and activation restrictions |
| 🛡️ [Detection Coverage](docs/DETECTION_COVERAGE.md) | Supported security checks and known gaps |
| ⚙️ [Benchmark Methodology](docs/INDUSTRY_BENCHMARK_SETUP.md) | Emulator matrix, validation and ephemeral file-handling rules |
| 📜 [License](LICENSE) & [Third-Party Notices](NOTICE) | Apache License 2.0 and third-party attribution |
| 🖼️ [Branding Assets](docs/BRANDING_ASSETS.md) | Official launcher icons and 512×512 Google Play listing artwork |

## Links

- **Official Website:** [VibeSyncro.com](https://vibesyncro.com/)
- **SafeMobile Product Page:** [SafeMobile](https://vibesyncro.com/safemobile.html)
- **Company About:** [About VibeSyncro](https://vibesyncro.com/about.html)

## Build & Verification

**Requirements:** JDK 17 and Android SDK 36.

~~~bash
# Unit tests and Android lint
./gradlew --no-daemon testOfflineDebugUnitTest lintOfflineDebug

# Assemble offline flavor for local testing
./gradlew --no-daemon assembleOfflineDebug
~~~

CI includes version guards, localization checks, offline tooling tests, lint, builds, and Android instrumented tests. Signed releases use private signing credentials and an independent release workflow.

**Package:** `com.vibesync.antivirus` · **Version:** `1.2.0` · **Version code:** `20261116` · **Android:** minSdk 26 / targetSdk 36.

## Responsible Security Disclosure

SafeMobile is **not a kernel-level security product** and cannot inspect every private file or guarantee detection of every malware family. OEM behavior, Android permissions, signature coverage and update timing affect results. The trained research model is **not** enabled for production detection.

Report vulnerabilities or reliability problems via [GitHub Issues](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues). **Do not attach malware binaries, credentials or personal scan data to public issues.**

## License & Attribution

SafeMobile project-owned source is licensed under **[Apache License 2.0](LICENSE)**. Third-party components keep their original licenses; consult [NOTICE](NOTICE), [third-party inventory](docs/THIRD_PARTY_LICENSES.md), [generated notices](THIRD_PARTY_NOTICES.md) and the [SBOM](docs/sbom.json).

<p align="center">
  <strong>SafeMobile Antivirus</strong><br>
  <em>Privacy by design. Security through evidence. Control stays with you.</em>
</p>
