#!/usr/bin/env python3
"""Fail CI if the offline release can access the network or any release packages ads/analytics SDKs."""
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
    b"com/google/android/gms/ads",
    b"com/google/android/ump",
    b"com/google/firebase",
    b"com/facebook/ads",
    b"com/facebook/appevents",
    b"com/facebook/analytics",
    b"com/segment/analytics",
    b"com/mixpanel/android",
    b"io/sentry",
    b"com/bugsnag",
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
    fail("aapt was not found; cannot inspect the APK manifest permissions.")

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

def dex_bytes(archive):
    hits = []
    for name in archive.namelist():
        if name.endswith(".dex"):
            hits.append((name, archive.read(name)))
    return hits

def has_false_boolean_attribute(xmltree_dump, attribute):
    """aapt dump xmltree reports compiled booleans as TYPE_INT_BOOLEAN hex values."""
    pattern = rf"android:{re.escape(attribute)}\\b[^\\n]*?(?:\\(type 0x12\\)\\s*0x0\\b|=\\s*false\\b)"
    return re.search(pattern, xmltree_dump, flags=re.IGNORECASE) is not None

def check_no_tracking_classes(path):
    try:
        with zipfile.ZipFile(path) as archive:
            for name, data in dex_bytes(archive):
                for marker in BAD_MARKERS:
                    if marker in data:
                        fail(path.name + " contains forbidden ad/analytics/crash SDK marker " + marker.decode())
    except zipfile.BadZipFile:
        fail("Cannot read release archive: " + str(path))

for apk in offline_apks:
    result = subprocess.run([aapt, "dump", "permissions", str(apk)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        fail("aapt could not read " + apk.name + ": " + result.stderr.strip())
    if "android.permission.INTERNET" in result.stdout:
        fail(apk.name + " declares INTERNET; offline release must not request it.")
    manifest_dump = subprocess.run([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"],
                                   text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if manifest_dump.returncode:
        fail("aapt could not inspect the manifest for " + apk.name)
    if not has_false_boolean_attribute(manifest_dump.stdout, "allowBackup"):
        fail(apk.name + " must have android:allowBackup=false.")
    if not has_false_boolean_attribute(manifest_dump.stdout, "fullBackupContent"):
        fail(apk.name + " must explicitly disable fullBackupContent.")
    if not has_false_boolean_attribute(manifest_dump.stdout, "hasFragileUserData"):
        fail(apk.name + " must set android:hasFragileUserData=false.")
    if "android:dataExtractionRules" not in manifest_dump.stdout:
        fail(apk.name + " must reference dataExtractionRules.")
    if "android.permission.MANAGE_EXTERNAL_STORAGE" in result.stdout or "android.permission.READ_EXTERNAL_STORAGE" in result.stdout:
        fail(apk.name + " declares broad/legacy storage access; use the SAF.")
    check_no_tracking_classes(apk)

for apk in feed_apks:
    result = subprocess.run([aapt, "dump", "permissions", str(apk)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode or "android.permission.INTERNET" not in result.stdout:
        fail(apk.name + " must explicitly contain INTERNET because this is the opt-in feed flavor.")
    check_no_tracking_classes(apk)

for bundle in release_bundles:
    check_no_tracking_classes(bundle)

print("Release privacy checks passed: offline APK has no INTERNET permission; release APKs/AABs contain no blocked ad, analytics, or crash-reporting SDK markers.")
