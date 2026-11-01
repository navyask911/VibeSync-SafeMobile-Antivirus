# SafeMobile Antivirus — Privacy Policy

**Effective / last reviewed: 1 November 2026**  
**App:** SafeMobile Antivirus (`com.vibesync.antivirus`)  
**Developer:** Navyask911 / VibeSync  
**Privacy contact:** [Open a GitHub repository issue](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues) (do not include private files, account details or malware samples).  
**Public policy:** https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/blob/main/docs/PRIVACY_POLICY.md

## 1. Overview: scanning stays on your device

SafeMobile's **core malware scanning works 100% offline**. Readable APKs, installed-app information, user-selected files, hashes, local signature checks, scan verdicts and scan history are processed on the device. SafeMobile does not transmit scanned APK contents, scan verdicts or device-posture snapshots to a developer-operated server. The Free tier includes Google AdMob advertising, which can process advertising-related identifiers and connection metadata as described in **Third-Party Advertising** below. These advertising-related data flows are disclosed separately from local malware scanning. Active SafeMobile Pro users are excluded from AdMob requests and ads.

**The whole app is not completely offline.** Optional signed threat-definition downloads and research ML-candidate updates use HTTPS to public GitHub-hosted services. User-initiated purchases use **Google Play Billing**. The Free tier also uses **Google AdMob** for advertising and Google's **User Messaging Platform (UMP)** for privacy choices. These providers and network infrastructure may process ordinary connection data, including IP addresses, under their own privacy terms. Active Pro entitlement prevents AdMob initialization and ad requests; it does not disable separately disclosed optional GitHub or user-initiated network functions. Core scans do not depend on these connections.

**Live Threat Intelligence Dashboard:** [Open the public dashboard](https://navyask911.github.io/safemobile-Antivirus-Trained-ML-Data-of-Android-malware/). The Live Threat Intelligence Dashboard is a public website that displays aggregated, anonymous ML training statistics. It is not part of the Android app and collects no data from SafeMobile users' on-device scans. The app sends no APK bytes, scan history, hashes, local analytics or identifiers to this dashboard; tapping the link opens the device's external browser. Visiting a public GitHub Pages website can expose ordinary browser/network metadata (such as IP address) to GitHub and its infrastructure, independently of the app.

## 2. Data accessed and retained locally

- **Installed-app inventory and APK information:** package names, app names, installation sources, requested permissions, locally accessible APK bytes, file digests and advisory risk results. The app requests broad package visibility to perform its core antivirus function; access to installed apps and sensitive permissions follows Android restrictions.
- **Selected files and folders:** only where the user grants system picker access or opts into folder/download monitoring; temporary parsing copies are removed after use where described in the in-app privacy notice.
- **Device posture:** metadata about Accessibility services, Device Administrator privileges, notification listeners and overlay permissions. SafeMobile does not read the contents of messages, displayed screens or notifications as part of this posture audit.
- **Security history and settings:** timestamps, scan outcomes, session information, locally collected app identifiers, security-alert preferences and optional monitoring snapshots; stored in app-private Room/DataStore and encrypted storage where supported.
- **Pro entitlement binding:** SafeMobile reads the app-scoped Android ID locally and stores a **SHA-256 hash of a namespaced, package-bound value** as a device fingerprint in Android Keystore-protected encrypted preferences. The raw ID and stored hash are **not uploaded** to the developer. The local ledger includes expiry, local check timestamps and **SHA-256 hashes of redeemed purchase tokens**, rather than persisting raw payment tokens.
- **Quarantined files:** protected in app-private storage where supported. Original files are not silently deleted by SafeMobile. The user's explicit actions govern quarantine, restore and removal.

No developer cloud account is created; there is no developer-controlled cloud backup of local scan history or Pro entitlements. Android app backup is disabled in the manifest.

## 3. Internet use and recipients

| Connection | When | Information involved |
|---|---|---|
| **GitHub Releases / public GitHub services** | Network-constrained download of signed malware-hash definitions (prepared by repository automation roughly every 6 hours, when available) and optional research ML candidates. | Requests for public signed files, model metadata and/or version information; **no scanned APKs, scan hashes or scan history are uploaded**. GitHub or network infrastructure may process request/IP metadata under their own policies. Files are cryptographically checked before accepted. |
| **Google AdMob / Mobile Ads Next-Gen SDK** | Free tier only, after UMP consent checks permit ad requests; banner ads appear on Home and an interstitial may appear after an eligible successful manual scan. | The SDK automatically collects and shares IP address; user product interactions (including app launches, taps and video views); diagnostic information (including app launch time, hang rate and energy usage); and device/account identifiers (including Android Advertising ID, App Set ID and, where applicable, identifiers associated with signed-in accounts). Google says this data is used for advertising, analytics and fraud prevention and is encrypted in transit with TLS. See Third-Party Advertising below. |\n| **Google Play Billing** | Only when the user opens the Pro purchase surface or checks out, to display product pricing and manage purchases. | Google Play processes payment and purchase records as an independent platform. SafeMobile receives transaction status, product, token and quantity in app memory to grant and consume the purchase. SafeMobile **does not collect, store or transmit credit-card, bank-account or payment-card information to its developer**. The raw purchase token is not stored in the local entitlement ledger or sent to a developer server. |
| **Optional user-specified HTTPS feed (`feed` flavor)** | Only after the user configures a feed endpoint, enables network consent and a release-trusted signing key is present. This is **not** the default Play `offline` flavor. | Signed indicators are downloaded; scan files and verdicts are not uploaded. The chosen feed host may see network/IP metadata. |

The separate **GitHub Actions malware-research/MLOps pipelines** run on repository infrastructure and process independently sourced research samples, not data uploaded by a person's installed SafeMobile app. A research model in the app is not automatically approved for production malware scoring.

## 4. SafeMobile Pro purchase and device binding

SafeMobile Pro offers a device-local **one-year consumable pass**; the current price is determined by Google Play checkout. **₹299/year is an intended India price, not a guaranteed or globally fixed charge.** Stacking is based on the actual quantity confirmed by Google Play.

The expiry and hashed device binding are encrypted locally and are **not cloud-synced or restorable**. After uninstalling SafeMobile, clearing app data, resetting the device, or losing Android Keystore keys, previously consumed passes may be irretrievable. No developer server can restore them. An outstanding unconsumed Play transaction may be retried through Google Play; previously consumed passes cannot be reconstructed from local data that no longer exists.

## 5. Storage security and retention

App-private storage is used for scans, histories and settings; selected sensitive items use **Android Keystore / encrypted preferences / Tink**. The app does not guarantee every historical record is end-to-end encrypted. Scan history and settings remain locally until deleted through supported in-app controls or the user clears app data or uninstalls. Some older quarantine entries may be less protected and are identified accordingly. No cross-device synchronization or developer-side data retention exists for those locally stored records.

**Deleting local information:** use Android Settings → Apps → SafeMobile Antivirus → Storage → Clear storage, or uninstall the app. Both permanently remove app-local scan records and may irreversibly destroy purchased Pro entitlements. Delete files outside app-private storage separately using Android's file manager. If you have a payment dispute, use Google Play's support/refund process because payments are handled by Google.

## 6. Permissions, disclosure and user choice

SafeMobile may request `QUERY_ALL_PACKAGES`, notifications, full-screen intent, foreground service, battery-optimization exemptions and file-picker access for antivirus, posture auditing, locally monitored downloads and incident alerts. Accessibility and device-administrator integrations have separately described purposes and require Android-mediated user enablement. The app does not secretly activate privileged access. Notifications/full-screen alerts and install-event receipt are subject to device settings and Android/OEM limitations.

Security findings are advisory; permission possession is not itself proof of malware.

## 7. Third-party services, children and changes

Google Play Billing and GitHub have their own privacy policies for their services and network requests. SafeMobile is a security utility, not specifically designed for children. We may update this policy if the app's capabilities, network access or data handling change; the published policy's effective date will change accordingly. The in-app notice is at [app/src/main/assets/privacy-policy.md](../app/src/main/assets/privacy-policy.md).

For privacy questions, use the repository's [Issues](https://github.com/navyask911/VibeSync-SafeMobile-Antivirus/issues). Avoid submitting sensitive information through public GitHub issues.

**Play Console requirement:** This policy should be made available at an accessible public HTTPS **rendered webpage** (not only a downloadable Markdown file), linked in the app and Play Console. Review the **Data safety** declaration and restricted-permission disclosures against the exact final signed AAB and third-party SDK behavior. This documentation is not a Play approval or independent legal review.

## 8. Official company and product websites

The following public websites provide company and product information:

- **Official company website:** https://vibesyncro.com/
- **SafeMobile product page:** https://vibesyncro.com/safemobile.html
- **About VibeSyncro:** https://vibesyncro.com/about.html

These links are opened only after a user chooses them in the app or visits them independently. The browser and website infrastructure may receive ordinary connection metadata, such as an IP address. SafeMobile does not append or transmit scanned APKs, file hashes, scan history, device identifiers or security findings to these websites.

## 9. Third-Party Advertising

The Free tier displays advertisements through **Google AdMob** using Google's **Mobile Ads Next-Gen SDK**. The app uses Google's **User Messaging Platform (UMP)** to refresh advertising privacy choices at app launch and present any required consent form before ad requests. According to Google's current Google Play data-disclosure documentation, the Next-Gen SDK automatically collects and shares the following categories for **advertising, analytics and fraud prevention**: **IP address** (which may be used to estimate general location); **user product interactions** (including app launches, taps and video views); **diagnostic information** (including app launch time, hang rate and energy usage); and **device/account identifiers** (including Android Advertising ID, App Set ID and, where applicable, other identifiers associated with signed-in accounts on the device). Google states that SDK data is encrypted in transit using **TLS**. The app does not send scanned APK contents, scan verdicts or locally stored scan history to AdMob. UMP choices, applicable law, jurisdiction and device settings affect whether advertising requests are permitted and what processing is allowed. An ordinary network connection can still expose an IP address to the relevant service provider. See Google's [Mobile Ads Next-Gen Google Play data-disclosure documentation](https://developers.google.com/ad-manager/mobile-ads-sdk/android/next-gen/privacy/play-data-disclosure) for the SDK's current categories; Google may update these disclosures as the SDK changes.

**SafeMobile Pro users are exempt from AdMob advertising and associated AdMob tracking/data collection.** While Pro is active on this device, SafeMobile does not initialize the Mobile Ads SDK and does not preload, request or display ads; therefore it does not send AdMob ad requests containing the Advertising ID or other ad-request metadata. SafeMobile checks the existing device-bound `checkProStatusForThisDevice()` entitlement before SDK initialization, each banner load and each interstitial display. If local entitlement status cannot be verified, ads remain disabled. This exemption applies to AdMob only; it does not make separate Google Play Billing, optional GitHub updates, or any explicitly enabled Global Threat Intelligence contribution tracker-free. Those services have their own separately described network processing.

Users can review or change advertising privacy choices using the in-app **Privacy and ad choices** entry point whenever UMP indicates that the entry point is required.

## 10. Optional Global Threat Intelligence contributions

Global Threat Intelligence contributions are **off by default and data-minimised**. It is designed so the contribution service does not receive personal user data, account details, device identifiers or location information in the contribution JSON. The app does not send a contribution unless the user explicitly enables **“Contribute to Global Threat Intelligence (Optional)”** in Settings and separately taps **Donate** for a confirmed malicious APK. Enabling the Settings switch alone sends nothing. **Decline**, leaving the switch OFF, or turning it OFF before submission means no contribution is sent.

After the two explicit consent actions, SafeMobile uses its bounded, on-device Drebin-215 extractor and sends only:
- the detected malicious APK's SHA-256 cryptographic hash; and
- the corresponding 215-value binary behavioral feature vector.

The request is an HTTPS POST to the VibeSync Cloudflare Worker. **The APK itself is never uploaded.** The JSON does not contain an APK filename, file contents, filesystem path, app/package name, scan history, account or user identity, Android ID, device fingerprint, contacts, messages or location. No GitHub access token, repository token or GitHub credential is embedded in the Android app. The app checks that the APK still has the detected SHA-256 before and after feature extraction; invalid, changed or unscannable files are not submitted. Upload or extraction failures do not interrupt scanning.

This is a data-minimised contribution flow; it is not a claim that the entire app performs no local data processing. Other app functions retain local records as described above (including scan history and the local, app-scoped Pro entitlement binding). Those local values are not included in threat contribution requests.

**Network metadata:** Cloudflare and internet infrastructure necessarily receive ordinary connection metadata, which may include an IP address and request timing. This connection metadata is separate from the contribution JSON. Worker-side logging, access controls and retention are configured by the Worker operator and are not independently audited by this Android client. The Worker is expected to retain only the threat intelligence needed for its stated purpose.
