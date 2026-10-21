#!/usr/bin/env python3
"""Detect the most harmful stale/overstated privacy and detection claims in the release docs."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")
COVERAGE = (ROOT / "docs/DETECTION_COVERAGE.md").read_text(encoding="utf-8")
MODEL_CARD = (ROOT / "docs/MODEL_CARD.md").read_text(encoding="utf-8")
SECURITY = (ROOT / "docs/SECURITY_MODEL.md").read_text(encoding="utf-8")
PERMISSIONS = (ROOT / "docs/PLAY_PERMISSIONS.md").read_text(encoding="utf-8")
LICENSE = ROOT / "LICENSE"
errors = []

for forbidden in ("Google Mobile Ads", "Google Play In-App Updates", "AD MOB", "com.google.android.gms.ads"):
    if forbidden in README:
        errors.append(f"README.md contains a removed integration claim: {forbidden}")
for required in ("EICAR test-marker", "No `INTERNET` permission", "not SQLCipher-encrypted", "Not a production-validated antivirus", "Detection coverage"):
    if required.lower() not in README.lower():
        errors.append(f"README.md missing required accuracy statement: {required}")
for required in ("Disabled", "No libyara JNI runtime", "not a production detection release", "no trained"):
    if required.lower() not in COVERAGE.lower():
        errors.append(f"Detection matrix missing required disabled-layer note: {required}")
if "No model is shipped or evaluated" not in MODEL_CARD:
    errors.append("MODEL_CARD.md must disclose that the model asset/evaluation is absent.")
if "Data-flow diagram" not in SECURITY or "Cryptographic inventory" not in SECURITY or "Room database is not SQLCipher-encrypted" not in SECURITY:
    errors.append("SECURITY_MODEL.md lacks flow, crypto inventory, or Room-encryption limitation.")
if "QUERY_ALL_PACKAGES" not in PERMISSIONS or "MANAGE_EXTERNAL_STORAGE — removed" not in PERMISSIONS:
    errors.append("PLAY_PERMISSIONS.md missing restricted permission coverage.")
if not LICENSE.exists() or LICENSE.stat().st_size < 8000 or "Apache License" not in LICENSE.read_text(encoding="utf-8"):
    errors.append("Root Apache-2.0 LICENSE is missing or incomplete.")
if errors:
    for err in errors:
        print("Release-doc check FAILED: " + err, file=sys.stderr)
    raise SystemExit(1)
print("Release-document accuracy checks passed.")
