# VibeSync-SafeMobile-Antivirus
High-performance native Android endpoint security engine featuring real-time heuristic threat detection, cryptographic APK signature indexing, and zero-egress cloud threat intelligence.
Act as a Principal Android Security Engineer. Scaffold and implement the production-grade native Android codebase for "VibeSync SafeMobile Antivirus" in Kotlin, adhering to MVVM + Clean Architecture, Jetpack Compose (Material 3), and strict Google Play security policies.

### 1. Project Specifications & Toolchain
- Application ID: com.vibesync.antivirus
- Min SDK: 26 (Android 8.0 Oreo)
- Target/Compile SDK: 35 (Android 15)
- Language & Build System: Kotlin with Gradle Kotlin DSL (`build.gradle.kts`)
- Concurrency: Kotlin Coroutines & StateFlow/SharedFlow
- Dependency Injection: Hilt (or clean manual DI factories if lightweight)
- Local Persistence & Security: Room Database, EncryptedSharedPreferences / Google Tink

---

### 2. Core Architectural Components to Implement

#### A. Cryptographic & Signature Engine (`core/crypto`, `core/engine`)
- Implement a thread-safe `HashCalculator` that streams file bytes to compute SHA-256 and MD5 checksums of APKs and binaries without loading large files into memory.
- Implement encrypted local definition storage using Google Tink to mask signature definitions at rest.
- Set up a Room database (`ThreatDatabase`) with indexed entity models for:
  - `ThreatSignature` (id, hash, malware_family, threat_level, date_added)
  - `ScanAudit` (id, package_or_path, hash, scan_timestamp, verdict, scan_duration)
  - `WhiteListEntry` (hash, package_name, certified_by)

#### B. Real-Time Sentinel & Background Sweeps (`core/observer`, `core/worker`)
- Implement a `StorageSentinelService` using Android's `FileObserver` to actively monitor high-risk system paths (e.g., `Environment.DIRECTORY_DOWNLOADS`) for new `.apk` or suspicious binary drop-ins.
- Implement a `PackageInstallReceiver` (`BroadcastReceiver`) listening to `ACTION_PACKAGE_ADDED` and `ACTION_PACKAGE_REPLACED` to automatically verify new installations against local threat hashes.
- Implement a battery-conscious `DeepScanWorker` using AndroidX `WorkManager` with `BatteryNotLow` and `DeviceIdle` constraints to run scheduled recursive partition scans.

#### C. Heuristic & Permission Risk Analyzer (`core/heuristics`)
- Create a `PermissionRiskAnalyzer` that inspects manifest capability clusters of installed packages (`QUERY_ALL_PACKAGES`), scoring threats when high-risk combinations appear together (e.g., `RECEIVE_BOOT_COMPLETED` + `SYSTEM_ALERT_WINDOW` + `BIND_ACCESSIBILITY_SERVICE` + `REQUEST_INSTALL_PACKAGES`).
- Check APK certificates to flag unverified self-signed or debug-signed packages.

#### D. Zero-Egress Cloud Threat Feeds (`data/remote`, `data/repository`)
- Implement a repository layer designed to fetch delta virus definition feeds from Cloudflare R2 (zero-egress distribution) and configuration signals from Supabase.
- Add an edge-case hash verification client for VirusTotal API lookups for unknown package hashes.

#### E. Presentation & Compliance UI (`presentation/`)
- Build a Jetpack Compose Material 3 interface:
  - **Dashboard:** System threat status, last scan timestamp, "Scan Now" button with progress radar.
  - **Scan Results:** Card list showing clean vs. flagged packages with quarantine/uninstall action intents.
  - **Prominent Privacy Disclosure Dialog:** A non-skippable, clear disclosure informing the user why file hashes are inspected on-device before requesting `MANAGE_EXTERNAL_STORAGE` or `QUERY_ALL_PACKAGES`.

---

### 3. Permissions & Manifest Setup (`AndroidManifest.xml`)
- Declare standard and special storage/package permissions:
  - `android.permission.MANAGE_EXTERNAL_STORAGE`
  - `android.permission.QUERY_ALL_PACKAGES`
  - `android.permission.FOREGROUND_SERVICE` & `android.permission.FOREGROUND_SERVICE_DATA_SYNC`
  - `android.permission.RECEIVE_BOOT_COMPLETED`
- Provide proper intent-filters for package installations and runtime storage listeners.

---

### 4. CI/CD & Testing
- Configure `.github/workflows/android-ci.yml` that runs on `push` and `pull_request` targeting `main`:
  - JDK 17 setup
  - Cache Gradle dependencies
  - Execute `./gradlew testDebugUnitTest` and `./gradlew lintDebug`
  - Assemble release and debug artifacts (`assembleDebug`)

Generate the full project directory layout, complete implementation code for all critical classes, and build files. Do not use placeholders or pseudo-code for the hashing pipeline, Tink integration, or Room database entities.
