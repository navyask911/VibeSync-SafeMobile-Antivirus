#!/usr/bin/env python3
"""Read-only localization quality gate. Never translates or rewrites source files."""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

BASE = Path("app/src/main/res")
LOCALES = (
    "es", "fr", "hi", "kn", "ru", "zh-rCN", "ja", "ar", "pt", "it",
    "ko", "tr", "vi", "id", "bn", "ta", "te", "mr", "gu", "ml",
    "pa", "ur",
)
FORMAT = re.compile(r"%(?:\\d+\\$)?[sdif]")
SOURCE_DIRS = (
    Path("app/src/main/java/com/vibesync/antivirus/presentation"),
    Path("app/src/main/java/com/vibesync/antivirus/ui"),
)
DIRECT_LITERALS = (
    re.compile(r'\\bText\\s*\\(\\s*(?:text\\s*=\\s*)?"([A-Za-z][^"]*)"'),
    re.compile(r'\\b(?:contentDescription|label)\\s*=\\s*"([A-Za-z][^"]*)"'),
    re.compile(r'\\bToast\\.makeText\\s*\\([^,]*,\\s*"([A-Za-z][^"]*)"'),
)
errors = []

def read_resources(path):
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        errors.append(f"{path}: XML could not be parsed ({type(exc).__name__})")
        return {}, {}
    strings, plurals = {}, {}
    for child in root:
        if child.tag not in ("string", "plurals"):
            continue
        key = child.attrib.get("name")
        if not key:
            errors.append(f"{path}: unnamed {child.tag} resource")
            continue
        bucket = strings if child.tag == "string" else plurals
        if key in bucket:
            errors.append(f"{path}: duplicate {child.tag} {key}")
        bucket[key] = child
    return strings, plurals

def formats(text):
    return sorted(FORM.findall(text or ""))

english, english_plurals = read_resources(BASE / "values" / "strings.xml")
for locale in LOCALES:
    path = BASE / f"values-{locale}" / "strings.xml"
    strings, plurals = read_resources(path)
    for key, base in english.items():
        if base.attrib.get("translatable", "true") == "false":
            continue
        if key not in strings:
            errors.append(f"{locale}: missing <string> {key}")
            continue
        expected = formats("".join(base.itertext()))
        actual = formats("".join(strings[key].itertext()))
        if expected != actual:
            errors.append(f"{locale}: placeholder mismatch for {key}: {expected} vs {actual}")
    for key, base in english_plurals.items():
        if key not in plurals:
            errors.append(f"{locale}: missing <plurals> {key}")
            continue
        items = plurals[key].findall("item")
        quantities = [item.attrib.get("quantity") for item in items]
        if len(quantities) != len(set(quantities)) or "other" not in quantities:
            errors.append(f"{locale}: duplicate quantity or missing other in {key}")
        english_other = base.find("item[@quantity='other']")
        expected = formats("".join(english_other.itertext())) if english_other is not None else []
        for item in items:
            quantity = item.attrib.get("quantity", "?")
            if formats("".join(item.itertext())) != expected:
                errors.append(f"{locale}: format mismatch in {key}/{quantity}")

# Preserve previous invariant: every existing locale must provide a voice warning.
for path in sorted(BASE.glob("values-*/strings.xml")):
    strings, _ = read_resources(path)
    item = strings.get("voice_alert_malware_detected")
    if item is None or not "".join(item.itertext()).strip():
        errors.append(f"{path}: missing voice_alert_malware_detected")

# Audit obvious literal UI labels on all Compose/Kotlin presentation components.
# Semantic inspection remains necessary for dynamic messages and names.
for folder in SOURCE_DIRS:
    for source in folder.rglob("*.kt"):
        text = source.read_text(encoding="utf-8")
        for pattern in DIRECT_LITERALS:
            for match in pattern.finditer(text):
                value = match.group(1)
                if value == "SafeMobile":
                    continue
                line = text.count("\\n", 0, match.start()) + 1
                errors.append(f"{source}:{line}: hardcoded user-facing text: {value[:55]}")

if errors:
    print("Localization check FAILED: " + str(len(errors)) + " error(s)")
    print("\\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Localization check passed: {len(LOCALES)} locales, string keys, plural forms, placeholders, voice alerts, and direct Compose literals.")
