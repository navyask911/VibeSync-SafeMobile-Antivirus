#!/usr/bin/env python3
"""Enforce complete Kannada/French translation keys and localized TTS strings."""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

base = Path("app/src/main/res")
pattern = re.compile(r"%(?:\d+\$)?[ds]")
def read(path):
    root = ET.parse(path).getroot()
    return {item.attrib["name"]: "".join(item.itertext()) for item in root.findall("string")}

english = read(base / "values/strings.xml")
errors = []
for locale in ("values-kn", "values-fr"):
    target = read(base / locale / "strings.xml")
    missing = sorted(english.keys() - target.keys())
    if missing:
        errors.append(f"{locale}: {len(missing)} untranslated/missing string keys: " + ", ".join(missing))
    for key, text in english.items():
        if key in target:
            expected = sorted(pattern.findall(text))
            actual = sorted(pattern.findall(target[key]))
            if expected != actual:
                errors.append(f"{locale}: argument placeholders differ for {key}: {expected} != {actual}")
for local in sorted(base.glob("values-*/strings.xml")):
    target = read(local)
    if not target.get("voice_alert_malware_detected", "").strip():
        errors.append(f"{local}: missing voice_alert_malware_detected")
if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Locale audit: Kannada and French have full English resource key parity and valid format placeholders; all locale voice warning strings exist.")
