
<div align="center">

# 🛡️ VibeSync SafeMobile Antivirus

**A native Android security app — offline-first, privacy-respecting, and built with modern Kotlin.**

[![Kotlin](https://img.shields.io/badge/Kotlin-2.x-7F52FF?logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-Material%203-4285F4?logo=jetpackcompose&logoColor=white)](https://developer.android.com/jetpack/compose)
[![Android](https://img.shields.io/badge/Android-API%2026–36-3DDC84?logo=android&logoColor=white)](https://developer.android.com)
[![Room](https://img.shields.io/badge/Room-Local%20DB-FF6F00)](https://developer.android.com/training/data-storage/room)
[![WorkManager](https://img.shields.io/badge/WorkManager-Scheduled%20Tasks-4CAF50)](https://developer.android.com/topic/libraries/architecture/workmanager)
[![Tink](https://img.shields.io/badge/Google%20Tink-Encryption-FFCA28?logo=google&logoColor=black)](https://developers.google.com/tink)

[![No Telemetry](https://img.shields.io/badge/Telemetry-None-brightgreen)](#-privacy--security)
[![No Cloud Uploads](https://img.shields.io/badge/Cloud%20Uploads-None-brightgreen)](#-privacy--security)
[![Offline First](https://img.shields.io/badge/Offline-First-blue)](#-overview)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-ff69b4)](#-contributing--bug-reports)
[![Made with ❤️](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red)](#)

[Repository](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus) · [Issues & Bug Reports](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues)

</div>

---

> ⚠️ **Development candidate, not a certified antivirus product.** SafeMobile combines local inspection, hashes, and heuristics to produce **risk indicators for review**, not definitive proof of maliciousness. Read [Known Limitations](#️-known-limitations) before relying on it.

---

## 🎯 Overview

SafeMobile is an **offline-first** Android security app that performs on-device APK/file inspection, hash lookups, permission and install-source heuristics, and local scan history — with optional, user-controlled network features (threat-feed sync, ads/consent, Play In-App Updates).

Core scanning runs locally. Network use is always **explicit, disclosed, and opt-in**.

---

## 🔏 Threat-intelligence engines

### (a) Existing JSON/CSV feed importer — available, unsigned

The existing user-configured HTTPS JSON/CSV threat-feed importer is implemented and available in the network-enabled flavor. It has **no default provider or automatic malware dataset**: a user must explicitly configure a trusted source and enable synchronization. Imported indicators are stored and matched locally; the scanner does not upload scanned files, their hashes, or scan results. The feed content is **not authenticated by a detached Ed25519 signature**. HTTPS transport and optional credentials alone do not establish publisher authenticity or malware-detection efficacy.

### (b) Phase A Ed25519-signed hash database — merged but inert

Phase A is **MERGED BUT DISABLED / INERT pending provisioning**. Its code supports MD5, SHA-1 and SHA-256, a Bloom pre-filter followed by exact indexed matches, detached Ed25519 verification, and monotonic signed-database version checks. No trusted signing public key or independently reviewed, redistributable production malware-hash database is bundled; the existing EICAR-only development marker is not real-world malware protection. **Phase A detects no production malware until the owner provisions a trusted key and imports a correctly signed database.**

To provision Phase A, the owner must generate and safeguard an Ed25519 keypair, configure the corresponding trusted public key in the release, obtain a redistributable malware-hash dataset with verified provenance and licence, convert it to a supported format such as `.hsb`, sign the exact database bytes, and import the signed bundle through Android's Storage Access Framework. Never commit the private key. See [signed database format and trust boundaries](docs/HASH_DATABASE_SIGNING.md) and [detection coverage](docs/DETECTION_COVERAGE.md).

The Phase B YARA runtime and Phase D ML/TFLite model remain **DISABLED**: no approved YARA Android runtime/rules or validated trained model is bundled. No detection-efficacy metrics are claimed; see [metrics on `main`](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/blob/main/docs/METRICS.md).

---

## ✨ Features

### 🔍 Detection & Scanning

| | Feature | Description |
|---|---|---|
| 📦 | **Local APK & file inspection** | Scans installed packages and user-selected files using standard app permissions. |
| 🔑 | **Hash lookups** | Matches file hashes against local/imported indicator sets. |
| 🛡️ | **Permission & install-source heuristics** | Flags risky permission combos and non-standard install sources. |
| 🗂️ | **Local scan history** | Persistent scan/audit records stored in Room. |
| 📊 | **Indexed imported indicators** | Fast lookups against imported threat indicators. |
| 🔁 | **Schema migrations** | Room migrations preserve existing scan history across upgrades. |
| ⏰ | **Scheduled scans** | Background scans via WorkManager (battery & network aware). |
| 🌐 | **Configurable threat-feed sync** | Optional HTTPS endpoint for local indicator synchronization. |
| 🔐 | **Feed credential encryption** | Credentials secured with Google Tink + Android Keystore. |
| 🧪 | **Mendeley dataset (dev only)** | Research dataset used for development — **not bundled** in release. |

### 🧊 Flagged-Result Actions

| | Action | Description |
|---|---|---|
| 👀 | **Review details** | Inspect the finding, evidence, and heuristic rationale. |
| ✖️ | **Dismiss finding** | Clear a false positive from the review queue. |
| 🧊 | **Quarantine** | Isolate an item (where supported) using Tink-encrypted storage. |
| 🛑 | **No auto-delete** | Nothing is deleted or blocked without explicit user action. |

### 🔐 Privacy & Security

| | Guarantee |
|---|---|
| 📴 | **Offline-first core** — scanning and audit flows run on-device. |
| 🚫 | **No telemetry** — no analytics or silent background uploads. |
| ☁️ | **No cloud uploads** — artwork/data never leaves the device by default. |
| 🧑‍⚖️ | **Consent-gated ads** — Google Mobile Ads + UMP only when configured and consent permits. |
| 🔒 | **Tink + Keystore** — quarantine artifacts and credentials are encrypted at rest. |
| 🧩 | **Disclosed network features** — threat-feed, ads, and Play In-App Updates are separate and optional. |

### 🎨 UI & Platform

| | Feature |
|---|---|
| 🖌️ | **Jetpack Compose Material 3** — modern, accessible UI. |
| 🔄 | **StateFlow MVVM** — predictable, testable presentation state. |
| 📲 | **Google Play In-App Updates** — prompt for available updates. |
| 🌍 | **Localization** — supported locales only (incomplete locales flagged). |
| ☕ | **Coffee support** — voluntary, not required for functionality. |

---

## 🏗️ Architecture Overview

- 🎨 **UI:** Jetpack Compose Material 3 with StateFlow-based MVVM.
- 🗄️ **Persistence:** Room stores scan/audit data and indexed imported indicators; migrations preserve history.
- 🔍 **Scanning:** Installed-package and user-selected-file paths use ordinary app permissions — Android sandboxing limits arbitrary system-partition access.
- 🔐 **Encryption:** Google Tink + Android Keystore protect quarantine and feed credentials.
- ⏰ **Background work:** WorkManager schedules supported scans and optional feed sync, subject to OS constraints.
- 🌐 **Optional network:** User-configured HTTPS threat feed, configured ads/consent, and Play update checks — all separate from the core local scan path.

> 🧭 **Don't assume** an optional model, Bloom filter, YARA runtime, third-party DB, or feed-signature verification exists unless its artifact and implementation are **separately verified**.

---

## ⚙️ Build Settings

| Setting | Value |
|---|---|
| 📦 Application ID | `com.vibesync.antivirus` |
| 📱 Min SDK | 26 |
| 🎯 Compile / Target SDK | 36 (Android 16) |
| ☕ JDK | 17 |
| 🧱 Build System | Gradle Kotlin DSL |
| 🏷️ Version Name | `1.0.2` |
| 🔢 Version Code | `20261022` (candidate; confirm unused in Play Console) |

---

## 🚀 Build, Test & Release

```bash
# Build a debug APK
./gradlew assembleDebug

# Run unit tests
./gradlew test

# Build a signed release (requires signing config)
./gradlew assembleRelease
```

> 🔑 Release builds require a properly configured signing keystore.

---

## 🧭 Security screens and merge status

The original Phase 4 hardening branch still exists, but its compliance foundation is already merged into `main`. Phase A (signed hash database, inert), Phase B (YARA disabled), Phase C (bounded local static risk analysis), and Phase D (ML disabled) have also been merged. **Phase E (capability UI, PR #12) and Phase F (provenance-gated metrics, PR #13) are still open and are not yet merged.** The security-focused screens include:

- 🛡️ **Security review dashboard**
- 🧾 **Findings detail & audit trail**
- 🧊 **Quarantine management**
- 🌐 **Threat-feed configuration**

> These are development features and may not appear in every build.

---

## 🌍 Localization status

**22 language resource sets are bundled**: English, Arabic, German, Spanish, French, Hindi, Japanese, Portuguese, Russian, Simplified Chinese, Korean, Turkish, Indonesian, Vietnamese, Italian, Kannada, Tamil, Telugu, Bengali, Marathi, Urdu and Hebrew. The in-app selector also offers System default. These are first-pass translations: resource-key and format-placeholder checks do not establish translation quality or device compatibility. **The number of languages confirmed to have passed both native-speaker review and on-device testing is not documented or independently verified**; do not treat all 22 as production-validated. Security/privacy copy, RTL layouts and text overflow still require review.

---

## ⚠️ Known Limitations

- 🚫 **Not a certified antivirus product** — results are heuristic risk indicators.
- 🧱 **No system-level scanning** — no kernel drivers or privileged access.
- ☁️ **No cloud-scale malware database** — detection is local-only.
- 🔬 **No independent security audit** — verification is limited to local testing.
- 🌍 **Unverified localization quality** — 22 language resources are bundled, but native-speaker and on-device validation remain unconfirmed.
- 🧪 **Optional features unverified** — model/YARA/signature artifacts must be checked before assuming presence.

---

## 🗺️ Roadmap

- [ ] 🧾 Verifiable feed-signature checking
- [ ] 🌍 Expanded localization coverage
- [ ] 🧪 Broader heuristic test corpus
- [ ] 📊 Scan performance profiling
- [ ] 🛡️ Independent security review

---

## 🤝 Contributing & Bug Reports

Contributions and bug reports are welcome via the [Issues page](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues).

1. 🍴 Fork the repository
2. 🌿 Create a branch (`git checkout -b feature/your-feature`)
3. 💾 Commit your changes
4. 🚀 Open a Pull Request

---

## 📄 License & Third-Party Components

The verified root [`LICENSE`](LICENSE) contains the **Apache License, Version 2.0 (Apache-2.0)** and a Navyask911 copyright notice. The repository also contains [`NOTICE`](NOTICE) and [`docs/THIRD_PARTY_LICENSES.md`](docs/THIRD_PARTY_LICENSES.md), which record third-party provenance and detection-engine licensing decisions. The CycloneDX SBOM and generated [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) track resolved dependencies; upstream licences, notices, and redistribution obligations must still be reviewed before commercial distribution.

---

## 📬 Contact

- 🐙 **Repository:** [navyask911/VibeSync-SafeMobile-Antivirus](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus)
- 🐞 **Issues:** [Report a bug](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues)

<div align="center">

**Built with 🛡️ by VibeSync · Privacy-first by design**

</div>
```


