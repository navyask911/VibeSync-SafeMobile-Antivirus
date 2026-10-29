
<div align="center">

# 🛡️ VibeSync SafeMobile Antivirus

**A native Android security app with on-device scanning and signed, GitHub Releases-only definition updates.**

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

## 🔏 Phase A — Signed local hash database

**Implemented but disabled by default.** The Phase A local hash engine supports MD5, SHA-1 and SHA-256, a Bloom pre-filter backed by exact indexed matching, detached Ed25519 verification, and monotonic database version checks. An EICAR-only development marker is not real-world malware protection. No trusted production Ed25519 public key or independently reviewed, redistributable malware-signature database is bundled, so **this engine does not provide active malware-signature detection until the owner provisions and imports a valid signed database**.

To enable the feature safely, the owner must generate and protect an Ed25519 signing keypair, configure the corresponding trusted public key for the intended release, obtain a dataset with confirmed redistribution rights and provenance, convert it to one of the supported hash-bundle formats (including `.hsb`), sign its exact bytes, and import the bundle via Android's Storage Access Framework. Never commit the private key or imply protection before provisioning. The optional network updater does not upload files, hashes, scan results or telemetry. See [signed database format and trust boundaries](docs/HASH_DATABASE_SIGNING.md) and [detection coverage](docs/DETECTION_COVERAGE.md).

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

## Optional owner-gated MalwareBazaar SHA-256 releases

The scheduled [signed hash database workflow (every 6 hours)](.github/workflows/update-malware-db.yml) builds versioned **hash-only SHA-256 indicator releases** from [MalwareBazaar (abuse.ch)](https://bazaar.abuse.ch/) after the owner has confirmed the source's redistribution rights, provisioned their API key and Ed25519 keypair, and configured the Android public-key trust root. **No malware sample binaries or threat database are bundled in APK/AAB artifacts.** The Android app checks only this repository's GitHub Releases and verifies each signed download before activation; it never contacts MalwareBazaar. Fair-use API access is not, by itself, a commercial redistribution licence; any published derived Release must credit the source and comply with its terms.

The Android app expects a signed ZIP containing `hashes.hsb` and `hashes.hsb.sig`, not two loose files. The current loader accepts at most **200,000 records and 16 MiB** of database text. The workflow **fails without publishing** if the full publisher export exceeds these bounds; it never silently truncates the feed. The signed hash engine remains **disabled pending owner provisioning**, and detection effectiveness remains **NOT_MEASURED**. See [setup, licensing and current limitations](docs/MALWAREBAZAAR_DB_WORKFLOW.md).


### Phase B — offline DEX signature subset

SafeMobile bundles five MIT-attributed, DEX-focused **YARA-compatible limited rules**, not libyara.
On startup the small bundled `.yar` is validated; any unsupported syntax disables **all** bundled rules.
On APK scanning, up to the existing bounded `classes*.dex` extracts are searched for exact ASCII
indicators combined with Boolean conditions, with rule name, severity, MITRE ID and string/pattern
evidence attached to advisory `RiskReport` findings. No network access or native code is used.
The detection capabilities screen shows **ACTIVE (LIMITED)** only on successful load, rule count
and the most recent displayed scan's match count. Imported rules remain review-only and
**never run**. These patterns may match legitimate code and do not catch decrypted-at-runtime,
native, or otherwise absent DEX content. The app has no claim of full YARA coverage or
real-world detection rate. See [docs/YARA_STATUS.md](docs/YARA_STATUS.md), [NOTICE](NOTICE),
and [the licence inventory](docs/THIRD_PARTY_LICENSES.md).

### v1.0.13: trust menus, install diagnostics and local charts

Trusted scan cards and incident details hide the primary uninstall action behind
a name-row options menu with Uninstall and Remove trust. Removal revokes package
and legacy digest overrides; displayed results are reassessed.

After privacy consent, opening SafeMobile starts a user-stoppable foreground
install sentinel. It listens for protected system package events without polling
or wake locks. A silent install notification proves receipt; the live service and
WorkManager share one serial, idempotent local scan processor. Confirmed threats
retain the five-second siren and permission-gated full-screen notification.
The reserved no-code test APK triggers a clearly marked diagnostic without a
database import or a fabricated malware record. Android/OEM force-stop restrictions
still apply; a persistent service cannot guarantee delivery in every device state.

Compose Canvas donut and weekly bar charts appear on the dashboard and analytics
screen. Room aggregates all stored audits and counts scan sessions, not individual
apps, for Monday–Sunday bars. No-match results and detected threats are not claimed
as guaranteed-safe files or blocked installations. New v1.0.13 strings are translated
directly in all 51 locale folders; earlier full coverage remains the 22 requested
languages. See [validation and physical-device checks](docs/V1_0_13_TESTING.md).

Overlay remediation passes the flagged app’s package URI and new-task flag. Android
11+ deliberately opens the global overlay list despite that URI; the app shows a
localized hint identifying which app to select.

### v1.0.12: user trust and native resource translations

User trust is an absolute, local package-name override. Marking an installed app
as trusted skips hash matching, DEX/YARA, permission models and heuristics, and
suppresses package alerts and Download Sentinel quarantine for that app. Trust
continues across updates and includes existing digest-based trust choices.
The UI marks these results **Safe (trusted by you)**; this is a user decision,
not a scan result. Untrusted packages retain automatic post-install scanning.

Translations are edited directly in Android XML resources, one locale at a
time. External translation clients and their generation scripts have been
removed. No translation service is contacted by the app or the normal build.
Resource checks preserve formatting placeholders and Android escaping. Coverage
of all 22 requested locales includes every one of the 700 default string keys,
including permission, incident, siren and download alerts. Other locale folders
retain Android fallback until separately translated.

### Research ML candidate update channel

With the existing on-device privacy acknowledgement, WorkManager checks the public training repository weekly using a CONNECTED-only network constraint. It queries GitHub's latest release, then checks recent prereleases because the training pipeline currently publishes a prerelease not returned by /latest. Downloads use OkHttp with timeouts, strict HTTPS redirects, a 20MB cap, matching GitHub release asset SHA-256 digests, the matching SHA256SUMS, 215-entry feature schema and research report. The temporary TFLite file is loaded, checked with one bounded inference, closed, and atomically moved to private app storage on success. Bad releases leave the old candidate unchanged. Local APK extraction now supports the frozen 215-feature schema, while production ML inference remains disabled: the bundled 32-feature file is still an untrained test fixture, and the 215-feature download is research-only. Hash and YARA scanning remain offline. **A 215-feature research candidate is never activated in production, regardless of benchmark scores.** Model upgrades require monotonically increasing vX.Y.Z-model tags; rewriting the same tag does not roll forward. No telemetry, scan data or APKs are sent to the training repository.

### v1.0.16 prerelease API and 215-feature extractor

The weekly updater now requests the training repository's `/releases?per_page=20` endpoint directly, including prereleases, and considers the first complete release in GitHub's newest-first list. A version tag must increase before any download. A fixed 215-key schema is bundled from the separate training repository; the updater requires the same schema checksum before replacing a private **inactive** model candidate. The on-device extractor parses binary AndroidManifest permissions and registered intent actions and uses a bounded DEX decoder for class/type information and invoked methods. Malformed or truncated APKs return an explicit unscannable outcome. Exact parity with the Python training extractor and independently validated modern detection performance are not yet established, and the model is therefore not activated. The release workflow can build and verify both signed offline APK and AAB once all release gates succeed.
