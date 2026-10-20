#!/usr/bin/env python3
"""Repository safety guard for proprietary identity and explicitly disallowed integrations.

This is a narrow CI guard, not a replacement for a full SBOM, licence audit, or secret scanner.
"""
from pathlib import Path
import re
import sys

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

# Permission-audit strings are allowed; an actual app-spying AccessibilityService subclass is not.
for path in (ROOT / "app" / "src" / "main").rglob("*.kt"):
    source = path.read_text(encoding="utf-8")
    if re.search(r':\s*(?:android\.accessibilityservice\.)?AccessibilityService\b', source):
        errors.append(
            f"AccessibilityService implementation found in {path.relative_to(ROOT)}; "
            "this policy prohibits app-screen/credential/OTP surveillance."
        )

if errors:
    print("Proprietary safety policy check FAILED:")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print("Proprietary safety policy check passed.")
print("This guard does not certify dependency licences, complete SBOM coverage, or Play Console eligibility.")
