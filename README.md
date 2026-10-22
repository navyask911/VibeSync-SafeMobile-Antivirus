
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
| 🔢 Version Code | `20261022` (hardening branch) |

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

## 🧭 Screens (Hardening Branch)

The hardening branch adds security-focused screens for review and audit:

- 🛡️ **Security review dashboard**
- 🧾 **Findings detail & audit trail**
- 🧊 **Quarantine management**
- 🌐 **Threat-feed configuration**

> These are development features and may not appear in every build.

---

## ⚠️ Known Limitations

- 🚫 **Not a certified antivirus product** — results are heuristic risk indicators.
- 🧱 **No system-level scanning** — no kernel drivers or privileged access.
- ☁️ **No cloud-scale malware database** — detection is local-only.
- 🔬 **No independent security audit** — verification is limited to local testing.
- 🌍 **Partial localization** — only bundled locales are complete.
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

Third-party libraries are used under their respective licenses. Review the [`LICENSE`](LICENSE) file and dependency licenses before redistribution.

---

## 📬 Contact

- 🐙 **Repository:** [navyask911/VibeSync-SafeMobile-Antivirus](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus)
- 🐞 **Issues:** [Report a bug](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues)

<div align="center">

**Built with 🛡️ by VibeSync · Privacy-first by design**

</div>
```


