#!/usr/bin/env python3
"""Repository safety guard for proprietary identity and explicitly disallowed integrations.

This is a narrow CI guard, not a replacement for a full SBOM, licence audit, or secret scanner.
"""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
GRADLE = ROOT / "app" / "build.gradle.kts"
EXPECTED_APPLICATION_ID = "com.vibesync.antivirus"

errors = []
gradle_text = GRADLE.read_text(encoding="utf-8")

if not re.search(r'applicationId\s*=\s*"' + re.escape(EXPECTED_APPLICATION_ID) + r'"', gradle_text):
    errors.append(f"Application ID must remain {EXPECTED_APPLICATION_ID}.")
if not re.search(r'namespace\s*=\s*"' + re.escape(EXPECTED_APPLICATION_ID) + r'"', gradle_text):
    errors.append(f"Android namespace must remain {EXPECTED_APPLICATION_ID}.")

# Integrations that need explicit licensing/terms approval are blocked at the dependency declaration
# layer. Documentation may discuss them; no client implementation or dependency is approved here.
blocked_coordinates = (
    "virustotal", "libclamav", "clamav-native", "org.clamav",
    "yara-java", "com.yara", "org.yara",
)
for line_number, line in enumerate(gradle_text.splitlines(), start=1):
    if re.search(r'\b(implementation|api|runtimeOnly|compileOnly|debugImplementation|releaseImplementation)\s*\(', line):
        lower = line.lower()
        for blocked in blocked_coordinates:
            if blocked in lower:
                errors.append(
                    f"Unapproved third-party scanner dependency '{blocked}' declared at "
                    f"app/build.gradle.kts:{line_number}; complete the licence approval gate first."
                )

# Catch common credential formats/private-key files in app source and build scripts. Public AdMob
# test identifiers are intentionally not treated as credentials.
secret_patterns = {
    "Google API key": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "PEM private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}
scan_roots = [ROOT / "app" / "src", ROOT / "app" / "build.gradle.kts", ROOT / ".github" / "workflows"]
allowed_suffixes = {".kt", ".kts", ".java", ".xml", ".json", ".yml", ".yaml", ".properties", ".pro"}
for base in scan_roots:
    files = [base] if base.is_file() else (p for p in base.rglob("*") if p.is_file())
    for path in files:
        if path.suffix.lower() not in allowed_suffixes:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in secret_patterns.items():
            if pattern.search(source):
                errors.append(f"Possible {label} found in {path.relative_to(ROOT)}; review without printing secret values.")

# Permission-audit strings are allowed, but SafeMobile must not implement or register an
# AccessibilityService. The Device Posture feature reads enabled-service metadata through the
# public AccessibilityManager list API; it must never bind to a service or inspect screen content.
MANIFEST = ROOT / "app" / "src" / "main" / "AndroidManifest.xml"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
ACCESSIBILITY_ACTION = "android.accessibilityservice.AccessibilityService"
ACCESSIBILITY_BIND_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"

try:
    manifest_root = ET.parse(MANIFEST).getroot()
except (ET.ParseError, OSError) as exc:
    errors.append(f"AndroidManifest.xml could not be parsed: {type(exc).__name__}.")
    manifest_root = None

if manifest_root is not None:
    for permission in manifest_root.findall("uses-permission"):
        if permission.get(ANDROID_NS + "name") == ACCESSIBILITY_BIND_PERMISSION:
            errors.append("SafeMobile must not request BIND_ACCESSIBILITY_SERVICE.")
    for service in manifest_root.findall("./application/service"):
        has_accessibility_action = any(
            action.get(ANDROID_NS + "name") == ACCESSIBILITY_ACTION
            for action in service.findall("./intent-filter/action")
        )
        has_accessibility_binding = service.get(ANDROID_NS + "permission") == ACCESSIBILITY_BIND_PERMISSION
        if has_accessibility_action or has_accessibility_binding:
            errors.append("SafeMobile must not declare an AccessibilityService in AndroidManifest.xml.")

for path in (ROOT / "app" / "src" / "main").rglob("*.kt"):
    source = path.read_text(encoding="utf-8")
    if re.search(r":\s*(?:android\.accessibilityservice\.)?AccessibilityService\b", source):
        errors.append(
            f"SafeMobile must not implement AccessibilityService: {path.relative_to(ROOT)}."
        )


# Device Posture may audit metadata and open Settings, but must never automate settings,
# inspect screen/notification content, change another app's policy, or contact a server.
POSTURE_SOURCE = ROOT / "app/src/main/java/com/vibesync/antivirus/core/posture"
POSTURE_INSPECTOR = POSTURE_SOURCE / "DevicePostureInspector.kt"
if not POSTURE_INSPECTOR.is_file():
    errors.append("Device Posture must include its metadata-only AccessibilityManager inspector.")
else:
    posture_inspector_source = POSTURE_INSPECTOR.read_text(encoding="utf-8")
    if not re.search(r"\bAccessibilityManager\b", posture_inspector_source) or not re.search(
        r"\bgetEnabledAccessibilityServiceList\s*\(", posture_inspector_source
    ):
        errors.append(
            "Device Posture must read enabled accessibility services using "
            "AccessibilityManager.getEnabledAccessibilityServiceList()."
        )
posture_forbidden = (
    r"\b(?:rootInActiveWindow|AccessibilityNodeInfo|NotificationListenerService)\b",
    r"\b(?:performGlobalAction|dispatchGesture|performAction|getRootInActiveWindow|bindService)\s*\(",
    r"Settings\.(?:Secure|Global|System)\.put\w*\s*\(",
    r"\b(?:setApplicationHidden|setPackagesSuspended|setUninstallBlocked|removeActiveAdmin|lockNow|wipeData)\s*\(",
    r"\b(?:ACTION_ADD_DEVICE_ADMIN|ACTION_DELETE|ACTION_UNINSTALL_PACKAGE)\b",
    r"\b(?:HttpURLConnection|HttpsURLConnection|OkHttpClient|Retrofit|Socket|WebView)\b",
    r"\bURL\s*\(",
)
for path in POSTURE_SOURCE.glob("*.kt"):
    source = path.read_text(encoding="utf-8")
    if any(re.search(pattern, source) for pattern in posture_forbidden):
        errors.append(f"Device Posture must remain a local, read-only metadata audit: {path.relative_to(ROOT)}.")

# All existing on-device security engines and incident response remain free of entitlement gates.
for area in ("engine", "observer", "posture", "hashdb", "quarantine", "security"):
    for path in (ROOT / "app/src/main/java/com/vibesync/antivirus/core" / area).glob("*.kt"):
        if re.search(r"\b(?:ProEntitlementStore|SafeMobileBillingManager|checkProStatusForThisDevice)\b",
                     path.read_text(encoding="utf-8")):
            errors.append(f"Core security must remain free of billing gates: {path.relative_to(ROOT)}.")

# Localization resource coverage and placeholder parity. This is a structural check, not a
# certification of translation quality or native-speaker review.
RESOURCES = ROOT / "app" / "src" / "main" / "res"
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[sdif]")

def read_string_resources(path: Path):
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        errors.append(
            f"Invalid Android string-resource XML at {path.relative_to(ROOT)}: {type(exc).__name__}."
        )
        return {}
    values = {}
    for element in root.findall("string"):
        name = element.attrib.get("name")
        if not name:
            errors.append(f"Unnamed <string> in {path.relative_to(ROOT)}.")
            continue
        if name in values:
            errors.append(f"Duplicate string resource '{name}' in {path.relative_to(ROOT)}.")
            continue
        values[name] = {
            "translatable": element.attrib.get("translatable", "true").lower() != "false",
            "text": "".join(element.itertext()),
        }
    return values

base_strings = read_string_resources(RESOURCES / "values" / "strings.xml")
for locale_file in RESOURCES.glob("values*/strings.xml"):
    if locale_file.parent.name == "values" or not locale_file.is_file():
        continue
    locale_strings = read_string_resources(locale_file)
    if not locale_strings:
        continue
    missing = [
        key for key, entry in base_strings.items()
        if entry["translatable"] and key not in locale_strings
    ]
    if missing:
        errors.append(
            f"Localization resource coverage incomplete in {locale_file.relative_to(ROOT)}: "
            f"{len(missing)} translated string(s) missing."
        )
    for key, entry in base_strings.items():
        translated = locale_strings.get(key)
        if not translated:
            continue
        expected = sorted(PLACEHOLDER.findall(entry["text"]))
        actual = sorted(PLACEHOLDER.findall(translated["text"]))
        if expected != actual:
            errors.append(
                f"Format placeholder mismatch for '{key}' in {locale_file.relative_to(ROOT)}."
            )

if errors:
    print("Proprietary safety policy check FAILED:")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("Proprietary safety policy check passed.")
print("This guard does not certify dependency licences, complete SBOM coverage, or Play Console eligibility.")

