#!/usr/bin/env python3
"""Static policy gate for consented Free-tier AdMob and strict local Pro exclusion."""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

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
billing = read("app/src/main/java/com/vibesync/antivirus/core/billing/SafeMobileBillingManager.kt")
billing_test = read("app/src/test/java/com/vibesync/antivirus/core/billing/SafeMobileBillingConfigurationTest.kt")
release_workflow = read(".github/workflows/release-apk.yml")
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

app_id = "ca-app-pub-4783826505860771~3262295335"
banner_id = "ca-app-pub-4783826505860771/4710308648"
interstitial_id = "ca-app-pub-4783826505860771/9523651625"
ads_resources = read("app/src/main/res/values/ads.xml")
debug_manifest = read("app/src/debug/AndroidManifest.xml")
feed_manifest = read("app/src/feed/AndroidManifest.xml")
try:
    ads_root = ET.fromstring(ads_resources)
except ET.ParseError as error:
    errors.append(f"app/src/main/res/values/ads.xml is invalid XML: {error}.")
    ads_root = None
app_id_entries = [] if ads_root is None else [
    item for item in ads_root.findall("string")
    if item.get("name") == "admob_app_id"
]
if len(app_id_entries) != 1:
    errors.append("Define exactly one default admob_app_id string resource.")
else:
    app_id_entry = app_id_entries[0]
    if (app_id_entry.text or "").strip() != app_id:
        errors.append("The default admob_app_id resource must match the approved AdMob App ID.")
    if app_id_entry.get("translatable", "true").lower() != "false":
        errors.append("The AdMob App ID resource must remain translatable=\"false\".")
if 'android:value="@string/admob_app_id"' not in manifest:
    errors.append("Manifest APPLICATION_ID metadata must reference @string/admob_app_id.")
if "InitializationConfig.Builder(getString(R.string.admob_app_id)).build()" not in app:
    errors.append("Application Mobile Ads initialization must read the shared admob_app_id resource.")
if app_id in manifest or app_id in app or app_id in gradle:
    errors.append("The AdMob App ID must be defined once in resources, not duplicated in app code or Gradle.")
if "ADMOB_APP_ID" in app:
    errors.append("Remove the duplicate hard-coded ADMOB_APP_ID constant; use the shared resource.")
if "ca-app-pub-" in debug_manifest or "com.google.android.gms.ads.APPLICATION_ID" in debug_manifest:
    errors.append("Debug manifest must not override the shared AdMob App ID.")
if "ca-app-pub-" in feed_manifest or "com.google.android.gms.ads.APPLICATION_ID" in feed_manifest:
    errors.append("Feed manifest must not override the shared AdMob App ID.")
if "com.google.android.gms:play-services-ads" in gradle:
    errors.append("Use the configured GMA Next-Gen SDK; do not add the legacy play-services-ads artifact.")
if "com.google.android.gms.ads.APPLICATION_ID" not in manifest:
    errors.append("Manifest must declare com.google.android.gms.ads.APPLICATION_ID.")
if "com.google.android.gms.permission.AD_ID" not in manifest:
    errors.append("Manifest must declare AD_ID for the disclosed Free-tier ad integration.")
if banner_id not in manager or interstitial_id not in manager:
    errors.append("Production banner/interstitial unit IDs must match the supplied AdMob IDs.")
if app_id not in release_workflow or "ca-app-pub-4783826505860771~8485727119" in release_workflow:
    errors.append("Release APK/AAB verifier must assert the approved AdMob App ID from values/ads.xml.")
if 'if [[ "$version_name" != "1.10.9" || "$version_code" != "20261163" ]]; then' not in release_workflow:
    errors.append("The main-branch release workflow must require candidate version 1.10.9 / versionCode 20261163.")
if "contains(github.event.head_commit.message, '[release-v1.10.9]')" not in release_workflow:
    errors.append("The main-branch signed release build must require the explicit v1.10.9 merge marker.")
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
# The banner is intentionally a Scaffold bottomBar child, not content above the
# weighted screen body. Scaffold applies safeDrawing insets to the entire chrome;
# scaffoldPadding is consumed by the content Column so the banner/navigation bar
# and scrollable body do not overlap system bars or each other.
scaffold_start = screen.find("Scaffold(")
scaffold_end = screen.find("snackbarHost =", scaffold_start) if scaffold_start >= 0 else -1
scaffold = screen[scaffold_start:scaffold_end] if scaffold_start >= 0 and scaffold_end > scaffold_start else ""
bottom_bar_start = scaffold.find("bottomBar = {")
bottom_bar = scaffold[bottom_bar_start:] if bottom_bar_start >= 0 else ""
banner_call = "AdMobBanner(adMobManager)"
if (
    not scaffold
    or bottom_bar_start < 0
    or banner_call not in bottom_bar
    or screen.count(banner_call) != 1
    or "if (adMobState.adsReady && !adMobState.isPro) AdMobBanner(adMobManager)" not in bottom_bar
    or "Column(Modifier.fillMaxWidth())" not in bottom_bar
    or "windowInsetsPadding(WindowInsets.safeDrawing)" not in scaffold
    or ") { scaffoldPadding ->" not in screen
    or "Column(Modifier.fillMaxSize().padding(scaffoldPadding))" not in screen
    or "AdSize.LEADERBOARD" not in banner
    or "adWidthDp >= 970" not in banner
    or "getCurrentOrientationAnchoredAdaptiveBannerAdSize(context" not in banner
):
    errors.append("AdMob banner must be the single adsReady/non-Pro child in the inset-aware Scaffold bottomBar, with 970 dp leaderboard/adaptive sizing and scaffold content padding.")

# Pin the published Play prepaid subscription configuration independently of
# the banner-placement rule. The existing Kotlin unit test also locks these IDs.
for expected in (
    'const val PRODUCT_ID = "safemobile-pro-1y-subs"',
    'const val PREPAID_BASE_PLAN_ID = "prepaid-1-year"',
    'const val PREPAID_BILLING_PERIOD = "P1Y"',
):
    if expected not in billing:
        errors.append(f"SafeMobile Pro billing configuration is missing: {expected}.")
for expected in (
    'assertEquals("safemobile-pro-1y-subs", SafeMobileBillingManager.PRODUCT_ID)',
    'assertEquals("prepaid-1-year", SafeMobileBillingManager.PREPAID_BASE_PLAN_ID)',
    'assertEquals("P1Y", SafeMobileBillingManager.PREPAID_BILLING_PERIOD)',
):
    if expected not in billing_test:
        errors.append(f"SafeMobile Pro billing configuration test is missing: {expected}.")
if (
    ".setProductId(PRODUCT_ID)" not in billing
    or "it.basePlanId == PREPAID_BASE_PLAN_ID && it.offerId == null" not in billing
    or "phase.billingPeriod == PREPAID_BILLING_PERIOD" not in billing
    or "phase.recurrenceMode == ProductDetails.RecurrenceMode.NON_RECURRING" not in billing
):
    errors.append("Play billing must continue to query only the configured non-recurring prepaid one-year plan.")

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

version_code_match = re.search(r"\bversionCode\s*=\s*(\d+)", gradle)
version_name_match = re.search(r'\bversionName\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', gradle)
if (
    version_code_match is None
    or int(version_code_match.group(1)) <= 0
    or version_name_match is None
):
    errors.append("The Android app must declare a positive versionCode and a semantic versionName.")
# Version monotonicity is enforced separately by scripts/check_version_code.py.
# This policy guard validates that Gradle exposes a well-formed positive app version.
if "On-device Malware Scanning. Ad-supported Free Tier. No AdMob Ads with Pro." not in readme:
    errors.append("README must use the requested Free/Pro advertising tagline.")
if "Ad-supported Free Tier" not in store or "Advertising ID" not in store or "IP address" not in store or "analytics" not in store:
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

# v1.9.0 removed Device Admin entirely. Keep the manifest free of the
# device-admin binding permission, activation intent, and receiver declaration.
for obsolete_admin_marker in (
    "android.permission.BIND_DEVICE_ADMIN",
    "android.app.action.DEVICE_ADMIN_ENABLED",
    "DeviceAdminReceiver",
):
    if obsolete_admin_marker in manifest:
        errors.append(
            f"SafeMobile v1.9.0 must not declare legacy Device Admin capability: {obsolete_admin_marker}."
        )
if (ROOT / "app/src/main/res/xml/device_admin_receiver.xml").exists():
    errors.append("Obsolete Device Admin receiver policy XML must be removed.")

if "android.permission.SYSTEM_ALERT_WINDOW" in manifest:
    errors.append("SafeMobile must not declare its unused own-overlay permission.")
for resource_file in sorted((ROOT / "app/src/main/res").glob("values*/strings.xml")):
    resource_text = read(str(resource_file.relative_to(ROOT)))
    try:
        ET.fromstring(resource_text)
    except ET.ParseError as error:
        errors.append(f"{resource_file.relative_to(ROOT)} is invalid XML: {error}.")
    if re.search(r"\\u(?![0-9a-fA-F]{4})", resource_text, re.IGNORECASE):
        errors.append(f"{resource_file.relative_to(ROOT)} contains a malformed Unicode escape.")
    if resource_file.parent.name == "values-tr":
        turkish_values = re.findall(r"<string\b[^>]*>([\s\S]*?)</string>", resource_text)
        if any(re.search(r"(?<!\\)'", value) for value in turkish_values):
            errors.append("values-tr/strings.xml contains an unescaped ASCII apostrophe; escape it as \\\\' in Android string resources.")
    if re.search(r"(?i)fully protected with a 100% security score", resource_text):
        errors.append(f"{resource_file.relative_to(ROOT)} retains the obsolete fully-protected score announcement.")
    if "force-lock and password policies" in resource_text or "screen-lock and password policy controls" in resource_text:
        errors.append(f"{resource_file.relative_to(ROOT)} still claims unsupported Device Admin password policies.")

if errors:
    print("AdMob policy check FAILED:")
    for error in errors:
        print("- " + error)
    sys.exit(1)

print("AdMob policy check passed: UMP consent, local Pro gate, approved units, disclosures and store copy.")
