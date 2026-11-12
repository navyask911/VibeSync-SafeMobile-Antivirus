# SafeMobile Antivirus v1.8.1 — Google Play Console Compliance Guide

**Application ID:** `com.vibesync.antivirus`  
**Release:** `1.8.1` (`versionCode 20261147`)  
**Build scope:** Android `offline` flavor is the Play Store build. The optional `feed` flavor is not the default Play build.  
**Purpose:** Antivirus scanning and device-security monitoring.

This document is a source-backed draft for the Play Console declarations. It is not evidence that Google has approved a permission, a foreground-service use case, a full-screen intent, or the Data Safety answers. The release owner must submit the forms and confirm the final merged AAB and each current SDK's disclosures.

---

## 1. `QUERY_ALL_PACKAGES` — installed-app inventory for core antivirus

**Manifest:** declared in `app/src/main/AndroidManifest.xml`.

**Suggested Play Console use-case description**

> SafeMobile Antivirus needs visibility of installed applications because scanning and reviewing the installed-app inventory is a core user-facing antivirus function. When the user opens the Apps or Scan features, the app enumerates installed user applications to inspect readable APKs locally, calculate file hashes, compare them with local threat definitions, and review declared permissions and components for security-risk indicators. Device Posture also uses installed-app metadata to identify enabled security-sensitive capabilities such as accessibility, administrator and overlay declarations. These checks are processed on the device. Installed-app inventory, package names and scan results are not uploaded to the developer, sold, or shared for advertising or analytics.

**How to demonstrate necessity to the reviewer**

- Show the Apps inventory and the user-initiated installed-app scan.
- Show local scan results and the permission/component risk review.
- Explain why a limited list of known packages cannot provide an antivirus scan of all user-installed apps.
- Explain that the visibility is for security functionality only, not advertising, analytics, audience profiling or monetisation.

**Implementation boundary:** the package scanner filters for user-installed applications and processes the inventory locally. The app must continue to use the smallest practical visibility scope and must not repurpose the inventory. Google Play treats installed-app inventory as sensitive data and requires a Play Console declaration; the Android platform lists security/antivirus apps as a potential broad-visibility use case, but broad visibility is not automatically approved.

---

## 2. `FOREGROUND_SERVICE_SPECIAL_USE` — user-visible security monitoring

**Manifest:** `FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_SPECIAL_USE` are declared. The application has two services with `android:foregroundServiceType="specialUse"`, each with a `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` explanation.

### Service A — Install Sentinel

**Manifest subtype text**

> User-visible on-device post-install security monitoring. Maintains a protected package-event receiver and processes install events locally; idle without polling or wake locks.

**Suggested Play Console declaration**

> Install Sentinel is an optional, user-enabled antivirus feature. After the user enables it in SafeMobile, a foreground service registers for Android package-install and package-replacement events and queues local post-install security inspection for newly installed or updated applications. The service runs on-device and does not upload APKs or scan results. An ongoing notification tells the user that monitoring is active and provides a Stop action. The user can disable the feature in SafeMobile or stop it from its notification.

### Service B — Storage Sentinel

**Manifest subtype text**

> User-enabled local Downloads folder monitoring to scan new APK files against local threat hashes.

**Suggested Play Console declaration**

> Storage Sentinel is an optional, user-enabled antivirus feature for a folder the user explicitly selects using Android's Storage Access Framework. While enabled and while the persisted folder grant remains valid, the foreground service checks accessible files in that selected folder and scans supported APKs locally against installed threat definitions. It does not request all-files access and does not scan arbitrary shared storage. The foreground notification makes monitoring visible; the user can turn the feature off or revoke the selected-folder grant.

**Reviewer evidence**

- Provide a video showing the user explicitly enabling each monitor.
- Show its ongoing foreground notification and Stop/disable control.
- Demonstrate that Storage Sentinel only monitors a user-selected SAF folder.
- Demonstrate that Install Sentinel is idle when disabled and processes package events locally when enabled.
- Explain why deferring these user-enabled monitoring tasks would defeat the user's expectation of prompt post-install/download inspection; do not claim guaranteed detection or uninterruptible operation.

**Important:** Play requires each foreground service to be beneficial and relevant to core app functionality, initiated by the user or user-perceptible, stoppable by the user, and not safely deferrable without harming the intended feature. A `specialUse` subtype description in the manifest does not itself establish approval.

---

## 3. `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` — optional continuity of safety monitoring

**Manifest:** declared in `app/src/main/AndroidManifest.xml`. The user reaches Android's system exemption request from the battery-guard control; SafeMobile does not silently grant itself an exemption.

**Suggested permission-use explanation**

> SafeMobile is an antivirus and device-safety application with optional user-enabled post-install and user-selected-folder security monitoring. On devices whose Doze or App Standby restrictions prevent those user-enabled monitoring services from running often enough to fulfil the monitoring feature, the user may choose to open Android's system battery-optimisation exemption screen for SafeMobile. The user makes the decision in Android settings and can decline or revoke the exemption. Core manual scanning remains available without this exemption.

**Do not claim:** that the exemption is required for manual scans, that it guarantees uninterrupted monitoring, or that the app is entitled to the exemption on every device. Google permits safety apps as a potential exception only where Doze/App Standby breaks the app's core function. If testing shows the direct exemption is not necessary, remove the permission and use normal battery-optimised scheduling instead of requesting it.

---

## 4. `AD_ID` and Google Mobile Ads Next-Gen — Data Safety

**Manifest:** declares `com.google.android.gms.permission.AD_ID`.  
**SDKs:** Google Mobile Ads Next-Gen SDK `1.6.0` and Google User Messaging Platform (UMP) `4.0.0`.

**Suggested Play Console advertising disclosure**

> The free version of SafeMobile displays Google AdMob advertising after the UMP privacy flow permits ad requests. The Google Mobile Ads Next-Gen SDK automatically collects and shares IP address, user product interactions (such as app launches, taps and video views), diagnostic information (such as app launch time, hang rate and energy usage), and device/account identifiers (including Android Advertising ID, App Set ID and, where applicable, identifiers associated with signed-in accounts). Google uses these categories for advertising, analytics and fraud prevention. SDK data is encrypted in transit using TLS. SafeMobile Pro disables AdMob SDK initialisation, ad preloading, ad requests and ad display while Pro is active on the device.

**Data Safety form checklist**

Use the current Play Console data-type taxonomy and the SDK's disclosure to complete the form. At a minimum, assess and disclose these SDK data categories:

| SDK information | Play Console data type to review | SDK purpose / handling |
|---|---|---|
| Android Advertising ID, App Set ID and applicable signed-in account identifiers | **Device or other IDs** | Collected/shared by the SDK for advertising, analytics and fraud prevention; Free tier only after UMP permits ad requests. |
| App launches, taps and video views | **App activity / App interactions** | Collected/shared by the SDK for advertising, analytics and fraud prevention. |
| App launch time, hang rate and energy usage | **App info and performance / Diagnostics** | Collected/shared by the SDK for diagnostics, analytics and fraud prevention. |
| IP address | **Review the current location/IP mapping in the Console form** | SDK says IP may be used to estimate a device's general location; do not omit it from the disclosure. |

For each relevant category, answer whether the data is collected, shared, processed ephemerally, required or optional, and the purposes according to the Play Console's current form and the actual SDK integration. Do not mark data as not collected merely because SafeMobile application code does not directly call an Advertising ID API: the SDK automatically processes these categories. UMP consent controls whether advertising requests may be made; it does not make the SDK's disclosed data categories disappear from the app's disclosure.

**Pro exemption:** SafeMobile checks the local Pro entitlement before Mobile Ads SDK initialisation and before ad request/display paths. When Pro is active, AdMob is not initialised and no ad requests are made by SafeMobile. Do not represent this conditional Pro behaviour as proof that the free tier does not collect/share advertising data.

**Also account for other app flows:** Global Threat Intelligence is off by default. When its master switch is enabled, the app automatically contributes confirmed-threat SHA-256 hashes (and, when available, a 215-value binary feature vector and verdict) to the VibeSync Cloudflare Worker. APK files and personal/device identifiers are not in the contribution JSON; Cloudflare/network infrastructure can still process IP address and request metadata. The published privacy policy describes this. Ensure the Data Safety form reflects the actual third-party transfer and data handling, not just the AdMob SDK.

---

## 5. Other permission and policy notes

- **Device inventory:** `QUERY_ALL_PACKAGES` is retained for the core antivirus installed-app inventory. It must not be used for ad targeting, analytics monetisation or unrelated profiling.
- **Protection Score:** the dashboard score is an advisory device-configuration/readiness rubric, not a percentage of malware detected, a probability of safety, or a guarantee of complete protection. A score of 100 means no currently measured configuration deductions remain; it does not mean the device is malware-free. Snoozing an unresolved check changes its reminder/presentation state only and does not restore its deduction. The score voice prompt now describes the configuration as optimized and does not claim that the device is fully protected.
- **Device Admin:** `device_admin_receiver.xml` now declares only `force-lock`. The app does not declare `wipe-data`, `watch-login`, `reset-password` or `limit-password`.
- **Overlay:** SafeMobile no longer declares `SYSTEM_ALERT_WINDOW` or asks users to grant its own overlay special access. Device Posture may still inspect metadata about other apps' overlay declarations/grants using Android APIs; it does not draw SafeMobile windows over other apps.
- **Accessibility:** the base manifest does not declare an app-owned `AccessibilityService`. Device Posture reads metadata about enabled third-party accessibility services; it does not bind to them, automate controls or read their screen contents.
- **APK self-updates:** `REQUEST_INSTALL_PACKAGES` is absent. Self-update uses Google Play's Play Core in-app update API.
- **Uninstall:** `REQUEST_DELETE_PACKAGES` is used with Android's user-confirmed uninstall flow; SafeMobile does not silently remove other apps.
- **Full-screen notifications:** the app uses an ordinary high-priority notification fallback when full-screen access is unavailable or rejected. Antivirus is not a calling or alarm app, so do not claim it qualifies for automatic full-screen-intent pre-grant. Complete any required Play Console declaration accurately and retain graceful degradation.
- **Battery optimisation:** the direct exemption request is optional and should remain only if evidence shows Doze/App Standby breaks a core security-monitoring function.
- **Privacy policy:** make the rendered HTTPS policy page publicly accessible and use the same current policy URL in the app and Play Console.

---

## 6. Before submitting the AAB

1. Upload the exact signed `offlineRelease` AAB and review its **merged manifest**, not only the source manifest.
2. Submit/confirm the `QUERY_ALL_PACKAGES` declaration and provide the in-app reviewer path/video.
3. Complete the special-use foreground-service declarations for both services and provide evidence of user initiation, ongoing notice and stop controls.
4. Verify the need for `REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`; keep the permission only if the core monitoring use case justifies it.
5. Complete Data Safety for Google Mobile Ads Next-Gen/UMP, Global Threat Intelligence, Google Play Billing and any other included SDKs or network recipients.
6. Review the separate `USE_FULL_SCREEN_INTENT` access and declaration. Do not assume an antivirus app is automatically eligible.
7. Confirm the public privacy policy, app listing, screenshots and in-app disclosures match the shipped v1.8.1 build.

## 7. Official references

- [Google Play: Permissions and APIs that access sensitive information](https://support.google.com/googleplay/android-developer/answer/16558241)
- [Android: Declare package visibility needs](https://developer.android.com/training/package-visibility/declaring)
- [Google Play: Permissions for Foreground Services](https://support.google.com/googleplay/android-developer/answer/18265346)
- [Android: Optimize for Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby)
- [Google Play: Full-screen intent requirements](https://support.google.com/googleplay/android-developer/answer/13392821)
- [Google: Google Mobile Ads Next-Gen Play data disclosure](https://developers.google.com/ad-manager/mobile-ads-sdk/android/next-gen/privacy/play-data-disclosure)

**Maintenance:** Re-check these official references and the latest version-specific SDK disclosures each time permissions, SDK versions, data flows or foreground-service behaviour change.
