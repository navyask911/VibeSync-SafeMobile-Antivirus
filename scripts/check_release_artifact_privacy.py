#!/usr/bin/env python3
"""Verify Play artifacts omit the signed hash database and unapproved analytics/crash SDKs."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
APK_ROOT = ROOT / "app" / "build" / "outputs" / "apk"
BUNDLE_ROOT = ROOT / "app" / "build" / "outputs" / "bundle"
BAD_MARKERS = (
    b"com/google/firebase",
    b"com/facebook/ads",
    b"com/facebook/appevents",
    b"com/facebook/analytics",
    b"com/segment/analytics",
    b"com/mixpanel/android",
    b"io/sentry",
    b"com/bugsnag",
)
FORBIDDEN_DB_ASSETS = (
    "safe-mobile-hashdb.bundle.zip",
    "hashes.hsb",
    "hashes.hsb.sig",
    "malware_hashes.hsb",
    "malware_hashes.sig",
)

def fail(message):
    print("Release privacy check FAILED: " + message, file=sys.stderr)
    raise SystemExit(1)

sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
aapt = shutil.which("aapt")
if not aapt and sdk:
    candidates = sorted((Path(sdk) / "build-tools").glob("*/aapt"))
    if candidates:
        aapt = str(candidates[-1])
if not aapt:
    fail("aapt was not found; cannot inspect APK manifests.")

offline_apks = list((APK_ROOT / "offline" / "release").glob("*.apk"))
feed_apks = list((APK_ROOT / "feed" / "release").glob("*.apk"))
release_bundles = list(BUNDLE_ROOT.rglob("*.aab"))
if not offline_apks:
    fail("offline release APK is missing; did assembleOfflineRelease run?")
if not feed_apks:
    fail("feed release APK is missing; did assembleFeedRelease run?")
if not any(p.name.lower().startswith("app-offline-release") for p in release_bundles):
    fail("offline release AAB is missing.")
if not any(p.name.lower().startswith("app-feed-release") for p in release_bundles):
    fail("feed release AAB is missing.")

def has_false_boolean_attribute(xmltree_dump, attribute):
    return re.search(
        rf"android:{re.escape(attribute)}\b[^\n]*?(?:\(type 0x12\)\s*0x0\b|=\s*false\b)",
        xmltree_dump, flags=re.IGNORECASE
    ) is not None

def inspect_artifact(path):
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            for name in names:
                basename = name.rsplit("/", 1)[-1]
                if basename in FORBIDDEN_DB_ASSETS and (name.startswith("assets/") or name.startswith("base/assets/")):
                    fail(path.name + " contains forbidden bundled database asset: " + name)
            for name in names:
                if name.endswith(".dex"):
                    data = archive.read(name)
                    for marker in BAD_MARKERS:
                        if marker in data:
                            fail(path.name + " contains unapproved legacy ad/analytics/crash SDK marker " + marker.decode())
                    if b"mb-api.abuse.ch" in data or b"bazaar.abuse.ch" in data:
                        fail(path.name + " contains a direct MalwareBazaar runtime endpoint.")
    except zipfile.BadZipFile:
        fail("Cannot read release archive: " + str(path))

def check_permissions(apk):
    result = subprocess.run([aapt, "dump", "permissions", str(apk)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        fail("aapt could not read " + apk.name + ": " + result.stderr.strip())
    if "android.permission.INTERNET" not in result.stdout:
        fail(apk.name + " must declare INTERNET for the GitHub Releases signed-database updater.")
    if "com.android.vending.BILLING" not in result.stdout:
        fail(apk.name + " must include Google Play Billing for the optional Pro purchase flow.")
    if any(permission in result.stdout for permission in (
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION")):
        fail(apk.name + " must not gain location permissions.")
    manifest = subprocess.run([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if manifest.returncode:
        fail("aapt could not inspect the manifest for " + apk.name)
    for attribute in ("allowBackup", "fullBackupContent", "hasFragileUserData"):
        if not has_false_boolean_attribute(manifest.stdout, attribute):
            fail(apk.name + " must explicitly set android:" + attribute + "=false.")
    if "android:dataExtractionRules" not in manifest.stdout:
        fail(apk.name + " must reference dataExtractionRules.")
    if "com.google.android.play.billingclient.version" not in manifest.stdout or "8.3.0" not in manifest.stdout:
        fail(apk.name + " must contain the supported Play Billing 8.3.0 manifest metadata.")
    if "com.google.android.gms.ads.APPLICATION_ID" not in manifest.stdout or "ca-app-pub-4783826505860771~8485727119" not in manifest.stdout:
        fail(apk.name + " must contain the configured AdMob application ID.")
    if "com.google.android.gms.permission.AD_ID" not in result.stdout:
        fail(apk.name + " must declare the Advertising ID permission for its disclosed Free-tier ad SDK.")
    if "android.permission.MANAGE_EXTERNAL_STORAGE" in result.stdout or "android.permission.READ_EXTERNAL_STORAGE" in result.stdout:
        fail(apk.name + " declares broad/legacy storage access; use the SAF.")
    inspect_artifact(apk)

for artifact in offline_apks + feed_apks:
    check_permissions(artifact)
for artifact in release_bundles:
    inspect_artifact(artifact)

print("Release privacy checks passed: APK/AAB artifacts omit the database and direct MalwareBazaar endpoints.")
