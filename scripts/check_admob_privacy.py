#!/usr/bin/env python3
"""Static policy gate for consented Free-tier AdMob and strict local Pro exclusion."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
errors = []

def read(relative):
    try:
        return (ROOT / relative).read_text(encoding="utf-8")
    except OSError:
        errors.append(f"Required file is missing: {relative}")
        return ""

gradle = read("app/build.gradle.kts")
main_activity = read("app/src/main/java/com/vibesync/antivirus/MainActivity.kt")
manifest = read("app/src/main/AndroidManifest.xml")
app = read("app/src/main/java/com/vibesync/antivirus/SafeMobileApp.kt")
manager = read("app/src/main/java/com/vibesync/antivirus/core/ads/AdMobManager.kt")
banner = read("app/src/main/java/com/vibesync/antivirus/presentation/AdMobBanner.kt")
screen = read("app/src/main/java/com/vibesync/antivirus/presentation/SafeMobileScreen.kt")
viewmodel = read("app/src/main/java/com/vibesync/antivirus/presentation/SafeMobileViewModel.kt")
privacy = read("docs/PRIVACY_POLICY.md")
asset_privacy = read("app/src/main/assets/privacy-policy.md")
readme = read("README.md")
store = read("docs/PLAY_STORE_DESCRIPTION.md")
about_readme = read("app/src/main/assets/README.md")

for coordinate in (
    "com.google.android.libraries.ads.mobile.sdk:ads-mobile-sdk:1.6.0",
    "com.google.android.ump:user-messaging-platform:4.0.0",
):
    if coordinate not in gradle:
        errors.append(f"Missing required AdMob/UMP dependency: {coordinate}.")

app_id = "ca-app-pub-4783826505860771~8485727119"
banner_id = "ca-app-pub-4783826505860771/4710308648"
interstitial_id = "ca-app-pub-4783826505860771/9523651625"
if app_id not in manifest or app_id not in app:
    errors.append("AdMob App ID must be in the manifest metadata and Application initialization config.")
if "com.google.android.gms:play-services-ads" in gradle:
    errors.append("Use the configured GMA Next-Gen SDK; do not add the legacy play-services-ads artifact.")
if "com.google.android.gms.ads.APPLICATION_ID" not in manifest:
    errors.append("Manifest must declare com.google.android.gms.ads.APPLICATION_ID.")
if "com.google.android.gms.permission.AD_ID" not in manifest:
    errors.append("Manifest must declare AD_ID for the disclosed Free-tier ad integration.")
if banner_id not in manager or interstitial_id not in manager:
    errors.append("Production banner/interstitial unit IDs must match the supplied AdMob IDs.")
if "/21775744923/example/adaptive-banner" not in manager or "/21775744923/example/interstitial" not in manager:
    errors.append("Debug builds must use Google's sample banner/interstitial ad units.")

if "checkProStatusForThisDevice()" not in app or "ProEntitlementStore" not in app:
    errors.append("AdMob SDK initialization must use the existing local ProEntitlementStore check.")
if app.count("getOrDefault(true)") < 2:
    errors.append("AdMob Pro lookup must fail closed when entitlement storage is unavailable.")
if "app.isProForAdMob()" not in manager or manager.count("app.isProForAdMob()") < 3:
    errors.append("Pro status must be rechecked before consent, banner/interstitial requests and display.")
if "adMobManager.refresh(this@MainActivity)" not in main_activity:
    errors.append("MainActivity must refresh UMP consent on every app launch.")
if "MobileAds.initialize" not in app or "initializeMobileAdsForFreeTier" not in manager:
    errors.append("Mobile Ads initialization must be owned by SafeMobileApp and called only by AdMobManager.")
if "requestConsentInfoUpdate" not in manager or "loadAndShowConsentFormIfRequired" not in manager:
    errors.append("UMP consent refresh and required-form presentation must precede ads.")
if "canRequestAds()" not in manager:
    errors.append("Every AdMob request path must check UMP canRequestAds().")
if "InterstitialAdPreloader.start" not in manager or "InterstitialAdPreloader.pollAd" not in manager:
    errors.append("Interstitial preloading and display methods are missing.")
if "InterstitialAdPreloader.destroy" not in manager:
    errors.append("Pro activation must destroy the preloaded interstitial cache.")
if "manager.canRequestAdsNow()" not in banner:
    errors.append("Banner load must recheck both Pro entitlement and UMP consent.")
if "manualScanCompletionSequence" not in viewmodel or "manualScanCompleted = true" not in screen:
    errors.append("Interstitials must be connected to successful manual-scan completion only.")
if "hasConfirmedThreats" not in manager or "state.threatCount > 0" not in screen:
    errors.append("Interstitial must be suppressed when confirmed threats are found.")
if "scanFull(manualScan = false)" not in screen:
    errors.append("Automatic first-run scans must not be treated as manual ad-trigger scans.")
if "selectedDestination == \"home\"" not in screen or "AdMobBanner(adMobManager)" not in screen:
    errors.append("Banner placement must be limited to the Home dashboard.")

for path, text in (
    ("docs/PRIVACY_POLICY.md", privacy),
    ("app/src/main/assets/privacy-policy.md", asset_privacy),
):
    for value in ("Google AdMob", "Advertising ID", "IP address", "analytics", "SafeMobile Pro"):
        if value not in text:
            errors.append(f"{path} is missing the advertising disclosure: {value}.")
    if "does not initialize" not in text and "does not initialise" not in text:
        errors.append(f"{path} must state the Pro AdMob exemption.")

for path, text in (
    ("docs/PRIVACY_POLICY.md", privacy),
    ("app/src/main/assets/privacy-policy.md", asset_privacy),
    ("README.md", readme),
    ("docs/PLAY_STORE_DESCRIPTION.md", store),
    ("app/src/main/assets/README.md", about_readme),
):
    lowered = text.lower()
    for value in ("user product interactions", "diagnostic information", "app set id", "tls"):
        if value not in lowered:
            errors.append(f"{path} is missing the complete Google Mobile Ads SDK disclosure: {value}.")

if 'versionCode = 20261116' not in gradle or 'versionName = "1.2.0"' not in gradle:
    errors.append("The Android app must be version 1.2.0 with versionCode 20261116.")
if "On-device Malware Scanning. Ad-supported Free Tier. No AdMob Ads with Pro." not in readme:
    errors.append("README must use the requested Free/Pro advertising tagline.")
if "Ad-supported Free Tier" not in store or "Advertising ID" not in store or "IP addresses" not in store or "analytics" not in store:
    errors.append("Google Play Store description must disclose ads and identifier/IP processing.")

for path, text in (
    ("docs/PRIVACY_POLICY.md", privacy),
    ("app/src/main/assets/privacy-policy.md", asset_privacy),
    ("README.md", readme),
    ("docs/PLAY_STORE_DESCRIPTION.md", store),
    ("app/src/main/assets/README.md", about_readme),
):
    if re.search(r"(?i)zero telemetry|zero scan telemetry|no trackers|no mobile advertising sdk|no ad sdk is added", text):
        errors.append(f"{path} still contains an obsolete zero-telemetry/no-ad claim.")

if errors:
    print("AdMob policy check FAILED:")
    for error in errors:
        print("- " + error)
    sys.exit(1)

print("AdMob policy check passed: UMP consent, local Pro gate, approved units, disclosures and store copy.")
