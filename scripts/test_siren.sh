#!/usr/bin/env bash
# Harmless valid APK fixture. Never downloads malware or changes the signed production database.
set -euo pipefail
siren_out="${1:-build/siren-test}"
siren_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
if [[ -z "$siren_sdk" || ! -d "$siren_sdk/build-tools" ]]; then
  echo 'Set ANDROID_SDK_ROOT or ANDROID_HOME to an Android SDK with platform 36 and build-tools.' >&2
  exit 1
fi
siren_tools="$(find "$siren_sdk/build-tools" -mindepth 1 -maxdepth 1 -type d | sort -V | tail -n 1)"
siren_platform="$siren_sdk/platforms/android-36/android.jar"
for siren_tool in aapt2 zipalign apksigner; do test -x "$siren_tools/$siren_tool"; done
test -f "$siren_platform"
command -v keytool >/dev/null
command -v python3 >/dev/null
mkdir -p "$siren_out"
siren_tmp="$(mktemp -d)"
trap 'rm -rf "$siren_tmp"' EXIT
cat > "$siren_tmp/AndroidManifest.xml" <<'XML'
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.safemobile.sirentest" android:versionCode="1" android:versionName="1.0">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="36" />
  <application android:label="SafeMobile Siren Test (Harmless)" android:hasCode="false" android:allowBackup="false" />
</manifest>
XML
"$siren_tools/aapt2" link -I "$siren_platform" --manifest "$siren_tmp/AndroidManifest.xml" -o "$siren_tmp/unsigned.apk"
"$siren_tools/zipalign" -f 4 "$siren_tmp/unsigned.apk" "$siren_tmp/aligned.apk"
# Public disposable fixture password. This is never the SafeMobile app's signing key.
keytool -genkeypair -keystore "$siren_tmp/fixture.jks" -storepass android -keypass android \
  -alias fixture -keyalg RSA -keysize 2048 -validity 3650 -dname 'CN=Harmless SafeMobile Siren Test' -noprompt >/dev/null 2>&1
"$siren_tools/apksigner" sign --ks "$siren_tmp/fixture.jks" --ks-key-alias fixture \
  --ks-pass pass:android --key-pass pass:android --out "$siren_out/SafeMobile-Siren-Test.apk" "$siren_tmp/aligned.apk"
"$siren_tools/apksigner" verify --verbose "$siren_out/SafeMobile-Siren-Test.apk"
"$siren_tools/aapt2" dump badging "$siren_out/SafeMobile-Siren-Test.apk" > "$siren_tmp/badging.txt"
python3 - "$siren_out" "$siren_tmp/badging.txt" <<'PY'
import hashlib, json, pathlib, sys, time, zipfile
out = pathlib.Path(sys.argv[1])
apk = out / 'SafeMobile-Siren-Test.apk'
badging = pathlib.Path(sys.argv[2]).read_text()
assert "package: name='com.safemobile.sirentest'" in badging
with zipfile.ZipFile(apk) as z:
    assert 'AndroidManifest.xml' in z.namelist()
    assert not any(n.endswith('.dex') for n in z.namelist()), 'Fixture must contain no executable code'
sha = hashlib.sha256(apk.read_bytes()).hexdigest()
definitions = {'schema_version': 1, 'definitions': [{'sha256': sha,
    'malware_family': 'SafeMobile.HarmlessSirenTest', 'threat_level': 'test', 'date_added': int(time.time()*1000)}]}
(out / 'siren-test-definitions.json').write_text(json.dumps(definitions, indent=2) + '\n')
(out / 'SHA256SUMS.txt').write_text(f'{sha}  {apk.name}\n')
print(f'Valid harmless fixture generated: {apk}\nSHA-256: {sha}')
PY
cat <<MSG

1. Enable Security Alerts in SafeMobile (and Voice Alerts if you want TTS).
2. Import $siren_out/siren-test-definitions.json through Scan > Import definitions.
   It is a local, explicitly selected test signature; production signed databases are untouched.
3. Enable Download Sentinel and choose a folder the system picker permits.
4. Copy $siren_out/SafeMobile-Siren-Test.apk into that granted folder AFTER importing the hash.
   Watch: adb logcat -s SafeMobileScan SafeMobileSentinel SafeMobileSecurityAlert
5. To test the post-install receiver instead, install the harmless APK after importing its hash:
   adb install "$siren_out/SafeMobile-Siren-Test.apk"
   (Uninstall an older fixture first if Android reports a signing mismatch.)
6. Clean up the test app: adb uninstall com.safemobile.sirentest

This APK contains no code, activities, network access or dangerous permissions.
Use the JSON generated alongside this exact APK: a new signing key produces a new hash each run.
MSG
