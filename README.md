```markdown
<div align="center">

# 🛡️ VibeSync SafeMobile Antivirus

### 🔒 Privacy-First • ☁️ Zero-Cloud • 🧠 On-Device Intelligence

**A modern, offline-first Android security platform built with Kotlin, Jetpack Compose & MVVM**

[![Kotlin](https://img.shields.io/badge/Kotlin-1.9+-7F52FF?style=for-the-badge&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![Jetpack Compose](https://img.shields.io/badge/Jetpack%20Compose-2024-4285F4?style=for-the-badge&logo=jetpackcompose&logoColor=white)](https://developer.android.com/jetpack/compose)
[![Android](https://img.shields.io/badge/Android-24%2B%20(10%2B)-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://developer.android.com)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue?style=for-the-badge)](LICENSE)

[![Author](https://img.shields.io/badge/Author-Navyask911-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/navyask911)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge)](CONTRIBUTING.md)
[![No Telemetry](https://img.shields.io/badge/Telemetry-NONE-red?style=for-the-badge)](#-privacy-guarantees)
[![No Cloud](https://img.shields.io/badge/Cloud-ZERO%20EGRESS-orange?style=for-the-badge)](#-privacy-guarantees)

</div>

---

## 📖 Table of Contents

- [🌟 Overview](#-overview)
- [🏗️ Multi-Layer Detection Engine](#️-multi-layer-detection-engine)
- [🔐 Privacy Guarantees](#-privacy-guarantees)
- [🧩 Feature Matrix](#-feature-matrix)
- [🚀 Getting Started](#-getting-started)
- [🧪 Build & Run](#-build--run)
- [🗂️ Architecture](#️-architecture)
- [🏢 Enterprise & MDM](#-enterprise--mdm)
- [📊 Detection Roadmap](#-detection-roadmap)
- [👤 Author](#-author)
- [🤝 Contributing](#-contributing)
- [⚠️ Disclaimer](#️-disclaimer)
- [📄 License & Copyright](#-license--copyright)

---

## 🌟 Overview

**VibeSync SafeMobile** is an Android antivirus and enterprise security platform designed around three core principles:

> **🔐 Privacy First** — No data ever leaves your device.  
> **🧠 On-Device Intelligence** — ML inference, YARA, and Bloom filters all run locally.  
> **🏢 Enterprise Ready** — Full Device Owner (MDM) support for IT administrators.

Unlike traditional antivirus apps that rely on cloud lookups and invasive telemetry, SafeMobile performs **100% of its scanning, analysis, and decision-making on the device itself** — delivering defense-in-depth without compromising user privacy.

---

## 🏗️ Multi-Layer Detection Engine

SafeMobile combines **five independent detection layers** to maximize coverage while remaining entirely offline:

```text
┌─────────────────────────────────────────────────────────────┐
│  📥 New App Installed / Periodic Scan Triggered            │
└──────────────────────────┬──────────────────────────────────┘
                           ▼
   ┌───────────────────────────────────────────────────────┐
   │  🧱 LAYER 1 — Static APK Inspection                   │
   │  • Manifest & permission extraction (top 30 risks)    │
   │  • YARA rules on DEX bytecode                         │
   │  • TFLite ML classifier (<1MB, ~1ms inference)        │
   └──────────────────────────┬────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────┐
   │  🧬 LAYER 2 — Curated Signature Database              │
   │  • HypatiaDatabases: ESET, ThreatFox, MalwareBazaar   │
   │  • Stalkerware IOCs                                   │
   │  • Guava BloomFilter lookup (O(k), ~20ms/1MB)         │
   └──────────────────────────┬────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────┐
   │  🎭 LAYER 3 — Heuristic & Behavioral Engine           │
   │  • Compound permission risk scoring                   │
   │  • Accessibility + Overlay = RAT indicator            │
   │  • Sideload provenance weighting                      │
   └──────────────────────────┬────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────┐
   │  🛡️ LAYER 4 — Device Integrity Check                  │
   │  • Offline root / Magisk / Xposed detection           │
   │  • Unified Attestation (offline, no identifiers)      │
   │  • Risk multiplier when device is tampered            │
   └──────────────────────────┬────────────────────────────┘
                              ▼
   ┌───────────────────────────────────────────────────────┐
   │  🏢 LAYER 5 — Enterprise Enforcement (Device Owner)   │
   │  • Silent quarantine via DevicePolicyManager          │
   │  • DISALLOW_INSTALL_UNKNOWN_SOURCES policy            │
   │  • Auto-uninstall on high-confidence verdicts         │
   └──────────────────────────┬────────────────────────────┘
                              ▼
                  ┌────────────────────────┐
                  │  📊 ThreatVerdict      │
                  │  • riskScore: Float    │
                  │  • reasons: List       │
                  │  • isMalware: Boolean  │
                  └────────────────────────┘
```

---

## 🔐 Privacy Guarantees

| Promise | How It's Enforced |
| :--- | :--- |
| 🚫 **No telemetry** | No analytics, no crash reporting SDKs, no usage pings. |
| ☁️ **Zero egress** | The scanner requires **no `INTERNET` permission** for scanning. |
| 🔐 **Encrypted metadata** | Threat family & level stored via **Google Tink AEAD**. |
| 📴 **Offline-first** | All ML, YARA, and Bloom filters bundled in `assets/`. |
| 🧾 **Local-only logs** | Room database never syncs; no backup to cloud. |
| 👁️ **Transparent permissions** | Every permission has a documented reason in `PERMISSIONS.md`. |

> ⚠️ SafeMobile will **never** upload your files, hashes, app list, or device identifiers to any server.

---

## 🧩 Feature Matrix

| Feature | Status | Notes |
| :--- | :---: | :--- |
| 📥 Install Source Verifier | ✅ | Detects sideloads from browsers & messengers |
| 🎯 Hash-based Detection | ✅ | SHA-256 + MD5 + SHA-1 Bloom filter (Layer 2) |
| 🧠 TFLite Permission Classifier | 🚧 | Layer 1 — training & bundling in progress |
| 🧬 YARA DEX Scanner | 🚧 | Layer 1 — JNI wrapper in progress |
| 🎭 Compound Risk Heuristics | ✅ | Permission clusters + provenance weighting |
| 🛡️ Root / Magisk Detection | 🚧 | Layer 4 — RootBeer integration planned |
| 🔑 Unified Attestation | 🚧 | Layer 4 — planned |
| 🏢 Device Owner / MDM | ✅ | Full provisioning + silent policy enforcement |
| 🔒 Silent Quarantine (DO mode) | ✅ | Requires Device Owner |
| 🚫 DISALLOW_UNKNOWN_SOURCES | ✅ | Auto-enforced in DO mode |
| 📊 Sideload Risk Audit UI | ✅ | Compose dashboard with green/orange badges |
| 📝 Incident Log (Room) | ✅ | Full metadata, queryable, exportable |
| 🔔 High-Priority Notifications | ✅ | NotificationCompat with deep links |
| 🔐 Tink-Encrypted Threat Metadata | ✅ | AEAD via Android Keystore |

**Legend:** ✅ Implemented · 🚧 In Progress · ⏳ Planned

---

## 🚀 Getting Started

### Requirements

- **Android Studio** Hedgehog (2023.1.1) or later
- **JDK** 17+
- **Android SDK** 34 (compile) / 24 (min)
- **Gradle** 8.x

### Clone the Repository

```bash
git clone https://github.com/navyask911/VibeSync-SafeMobile-Antivirus.git
cd VibeSync-SafeMobile-Antivirus
```

### 🔑 Configure Signing (for release builds)

```bash
cp keystore.properties.example keystore.properties
# Edit keystore.properties with your signing credentials
```

---

## 🧪 Build & Run

### Debug build

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### Release build

```bash
./gradlew assembleRelease
```

### Run tests & lint

```bash
./gradlew test lint
```

> ✅ CI enforces **zero lint errors** and **no hardcoded secrets**.

---

## 🗂️ Architecture

SafeMobile follows strict **MVVM + Clean Architecture** with coroutine-driven state flows:

```text
app/
├── data/
│   ├── local/          # Room: ThreatDao, IncidentDao, MalwareHashDao
│   ├── remote/         # ⚠️ EMPTY — no network by design
│   ├── crypto/         # Google Tink wrappers
│   └── repository/     # ThreatRepository, ScanRepository
├── domain/
│   ├── engine/         # Layer 1–4 scanners
│   │   ├── StaticAnalyzer.kt
│   │   ├── YaraScanner.kt
│   │   ├── BloomFilterScanner.kt
│   │   ├── PermissionRiskAnalyzer.kt
│   │   └── IntegrityChecker.kt
│   ├── enterprise/     # Layer 5 — DeviceOwnerManager
│   └── model/          # ThreatVerdict, InstallSourceClassification
├── ui/
│   ├── dashboard/      # Main screen + Sideload Risk Audit
│   ├── onboarding/     # First-run + Enterprise Setup card
│   ├── scan/           # Scan progress & results
│   └── theme/          # Compose design system
├── receiver/
│   ├── PackageInstallReceiver.kt
│   └── AdminReceiver.kt
├── worker/
│   ├── MultiLayerScanWorker.kt
│   └── DeepScanWorker.kt
└── assets/
    ├── malware_model.tflite
    ├── yara_rules/
    └── hypatia_bloom.db
```

---

## 🏢 Enterprise & MDM

SafeMobile supports full **Device Owner** provisioning for IT administrators.

### 📲 Provision via ADB (testing)

```bash
adb shell dpm set-device-owner \
    com.vibesync.antivirus/.receiver.AdminReceiver
```

### 📷 Provision via QR code (production)

Generate a provisioning QR code with the following payload:

```json
{
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME":
    "com.vibesync.antivirus/.receiver.AdminReceiver",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION":
    "https://your-server/antivirus.apk",
  "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_CHECKSUM":
    "BASE64_SHA256_CHECKSUM"
}
```

### 🔓 Unlocked in Device Owner Mode

- 🔒 **Silent quarantine** of flagged apps (`setApplicationHidden`)
- 🚫 **Silent uninstall** on high-confidence malware
- 🛡️ **Auto-enforce** `DISALLOW_INSTALL_UNKNOWN_SOURCES`
- 🔐 Enforce password policies & lock USB debugging

When Device Owner is **not** active, SafeMobile gracefully falls back to **Standard Mode** — fully functional user-managed monitoring with clear ADB setup instructions shown in the onboarding card.

---

## 📊 Detection Roadmap

| Milestone | Target | Status |
| :--- | :---: | :---: |
| Replace EICAR-only hash DB with HypatiaBloom | v1.1 | 🚧 |
| Bundle TFLite permission classifier | v1.2 | 🚧 |
| YARA DEX scanner (JNI) | v1.2 | 🚧 |
| Offline root/Magisk detection | v1.3 | ⏳ |
| Unified Attestation integration | v1.3 | ⏳ |
| **Target: >90% offline detection** | **v2.0** | 🎯 |

---

## 👤 Author

<div align="center">

**Navyask911**

[![GitHub](https://img.shields.io/badge/GitHub-navyask911-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/navyask911)
[![Repository](https://img.shields.io/badge/Repo-VibeSync--SafeMobile--Antivirus-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus)

*Creator, maintainer, and sole copyright holder of the VibeSync SafeMobile Antivirus project.*

</div>

---

## 🤝 Contributing

Contributions are welcome! Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) first.

```bash
# Fork → branch → code → test → PR
git checkout -b feat/your-feature
./gradlew test lint
git commit -m "feat: add your feature"
git push origin feat/your-feature
```

### 🐛 Found a bug?

Open an [issue](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues) with:
- Device model & Android version
- Steps to reproduce
- Logcat snippet (redact sensitive data)

---

## ⚠️ Disclaimer

> **SafeMobile is an independent, open-source project created and owned by Navyask911.**  
> It is **not affiliated with Google, Apple, or any commercial antivirus vendor**.  
> Detection capabilities are under active development. Do **not** rely on this build as your sole line of defense until the v2.0 roadmap is complete. See [Detection Roadmap](#-detection-roadmap).

---

## 📄 License & Copyright

```text
Copyright (c) 2024-2026 Navyask911
All rights reserved where applicable.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

> 📌 **Ownership Notice:** The VibeSync SafeMobile Antivirus project, including all original source code, documentation, artwork, and branding, is the intellectual property of **Navyask911**. The Apache 2.0 license applies to the source code as published in this repository. All project branding and the "VibeSync SafeMobile" name remain the property of the author.

---

<div align="center">

### 🌟 Star this repo if you believe in privacy-first security

**Made with ❤️ by [Navyask911](https://github.com/navyask911)**

[⬆ Back to Top](#️-vibesync-safemobile-antivirus)

</div>
```

---

### 📌 What changed in this revision

| Section | Update |
| :--- | :--- |
| **Badges** | Removed the generic License-only badge row; added an **Author: Navyask911** badge at the top. |
| **Author section** | New dedicated section with GitHub + Repo badges, explicitly stating Navyask911 is creator, maintainer, and **sole copyright holder**. |
| **Disclaimer** | Now names **Navyask911** as project creator and owner. |
| **License & Copyright** | Copyright line changed to `Copyright (c) 2024-2026 Navyask911`. Added an **Ownership Notice** clarifying code license vs. branding ownership. |
| **Footer** | "Made with ❤️ by **Navyask911**" with GitHub link. |
| **Clone/Issue URLs** | All point to `navyask911` (consistent with your GitHub handle). |
| **Table of Contents** | Added the new **Author** section. |

### ✅ One more thing to do outside the README

Make sure your actual **`LICENSE`** file in the repo root starts with:

```
Copyright (c) 2024-2026 Navyask911

Licensed under the Apache License, Version 2.0 ...
```
