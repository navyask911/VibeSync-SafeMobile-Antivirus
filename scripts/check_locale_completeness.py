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
    "af", "az", "bg", "ca", "cs", "da", "de", "el", "et", "fa",
    "fi", "fil", "b+he", "hr", "hu", "ka", "kk", "lt", "lv", "ms",
    "nb", "ne", "nl", "pl", "ro", "sk", "sv", "th", "uk",
)
FORMAT = re.compile(r"%(?:\d+\$)?[sdif]")
SOURCE_DIRS = (
    Path("app/src/main/java/com/vibesync/antivirus/presentation"),
    Path("app/src/main/java/com/vibesync/antivirus/ui"),
)
DIRECT_LITERALS = (
    re.compile(r'\bText\s*\(\s*(?:text\s*=\s*)?"([A-Za-z][^"]*)"'),
    re.compile(r'\b(?:contentDescription|label)\s*=\s*"([A-Za-z][^"]*)"'),
    re.compile(r'\bToast\.makeText\s*\([^,]*,\s*"([A-Za-z][^"]*)"'),
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
    return sorted(FORMAT.findall(text or ""))

english, english_plurals = read_resources(BASE / "values" / "strings.xml")
INTELLIGENCE_KEYS = tuple("threat_intelligence_" + name for name in (
    "title", "samples", "accuracy", "downloads", "updated", "updating", "training_note"
))
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
    for key in INTELLIGENCE_KEYS:
        source, translated = english.get(key), strings.get(key)
        if source is None:
            errors.append(f"base strings.xml: missing intelligence string {key}")
        elif translated is not None:
            text_value = "".join(translated.itertext()).strip()
            if not text_value or text_value == "".join(source.itertext()).strip():
                errors.append(f"{locale}: empty or English intelligence fallback {key}")
    for key, base in english_plurals.items():
        if key not in plurals:
            errors.append(f"{locale}: missing <plurals> {key}")
            continue
        items = plurals[key].findall("item")
        quantities = [item.attrib.get("quantity") for item in items]
        if len(quantities) != len(set(quantities)) or "other" not in quantities:
            errors.append(f"{locale}: duplicate quantity or missing other in {key}")
        if locale in {"az", "bn", "hu", "ka", "mr", "ta", "te", "tr"} and "one" not in quantities:
            errors.append(f"{locale}: missing required one quantity in {key}")
        english_other = base.find("item[@quantity='other']")
        expected = formats("".join(english_other.itertext())) if english_other is not None else []
        for item in items:
            quantity = item.attrib.get("quantity", "?")
            if formats("".join(item.itertext())) != expected:
                errors.append(f"{locale}: format mismatch in {key}/{quantity}")

# v1.0.20: English and all 51 translated resource folders must expose a
# genuinely localized dashboard label. The hardcoded HTTPS URL is not translatable.
DASHBOARD_LABEL = "threat_intelligence_live_dashboard_link"
dashboard_base, _ = read_resources(BASE / "values" / "live_dashboard.xml")
dashboard_source = dashboard_base.get(DASHBOARD_LABEL)
if dashboard_source is None:
    errors.append("base live_dashboard.xml: missing label")
for locale in LOCALES:
    dashboard_labels, _ = read_resources(BASE / f"values-{locale}" / "live_dashboard.xml")
    target = dashboard_labels.get(DASHBOARD_LABEL)
    if target is None:
        errors.append(f"{locale}: missing dashboard label")
        continue
    localized = "".join(target.itertext()).strip()
    source_value = "".join(dashboard_source.itertext()).strip() if dashboard_source is not None else ""
    if not localized or localized == source_value:
        errors.append(f"{locale}: empty or English dashboard label fallback")
    if formats(localized) != formats(source_value):
        errors.append(f"{locale}: dashboard label format mismatch")

# v1.0.16 uses a separate, small resource file per locale. Verify all 51 translations
# are present, non-English fallbacks, XML-valid, and placeholder compatible.
V116_KEYS = ("v116_scan_title", "v116_scan_local_no_match", "v116_score_meaning")
base_v116, _ = read_resources(BASE / "values" / "v116.xml")
for key in V116_KEYS:
    if key not in base_v116:
        errors.append(f"base v116.xml: missing {key}")
for locale in LOCALES:
    localized, _ = read_resources(BASE / f"values-{locale}" / "v116.xml")
    for key in V116_KEYS:
        value = localized.get(key)
        base_value = base_v116.get(key)
        if value is None:
            errors.append(f"{locale}: missing v1.0.16 translation {key}")
            continue
        text_value = "".join(value.itertext()).strip()
        if not text_value:
            errors.append(f"{locale}: empty v1.0.16 translation {key}")
        if base_value is not None:
            english_value = "".join(base_value.itertext()).strip()
            if text_value == english_value:
                errors.append(f"{locale}: v1.0.16 English fallback {key}")
            if formats(text_value) != formats(english_value):
                errors.append(f"{locale}: v1.0.16 placeholder mismatch {key}")

# v1.1.0: dedicated Global Threat Intelligence contribution copy must be
# present and genuinely translated in the base locale plus all 51 translations.
GLOBAL_TI_KEYS = (
    "global_threat_intelligence_title",
    "global_threat_intelligence_description",
    "global_threat_intelligence_donate_message",
    "global_threat_intelligence_donate",
    "global_threat_intelligence_decline",
)
base_global_ti, _ = read_resources(BASE / "values" / "global_threat_intelligence.xml")
for key in GLOBAL_TI_KEYS:
    if key not in base_global_ti:
        errors.append(f"base global_threat_intelligence.xml: missing {key}")
for locale in LOCALES:
    translated, _ = read_resources(BASE / f"values-{locale}" / "global_threat_intelligence.xml")
    for key in GLOBAL_TI_KEYS:
        source, target = base_global_ti.get(key), translated.get(key)
        if target is None:
            errors.append(f"{locale}: missing Global Threat Intelligence string {key}")
            continue
        value = "".join(target.itertext()).strip()
        original = "".join(source.itertext()).strip() if source is not None else ""
        if not value or value == original:
            errors.append(f"{locale}: empty or English Global Threat Intelligence fallback {key}")
        if formats(value) != formats(original):
            errors.append(f"{locale}: Global Threat Intelligence placeholder mismatch {key}")

# Preserve previous invariant: every existing locale must provide a voice warning.
# Paid purchase disclosures must never fall back to English in any supported locale.
# SafeMobile Pro and Google Play are product brands, not untranslated sentences.
base_pro, _ = read_resources(BASE / "values" / "pro.xml")
for locale in LOCALES:
    pro, _ = read_resources(BASE / f"values-{locale}" / "pro.xml")
    if set(pro) != set(base_pro):
        errors.append(f"{locale}: paywall key set differs from base pro.xml")
    for key, source in base_pro.items():
        target = pro.get(key)
        if target is None:
            continue
        value = "".join(target.itertext()).strip()
        original = "".join(source.itertext()).strip()
        if not value or (key != "pro_title" and value == original):
            errors.append(f"{locale}: empty or English paywall fallback {key}")
        if formats(value) != formats(original):
            errors.append(f"{locale}: paywall placeholder mismatch {key}")
        if key == "pro_device_disclaimer" and target.attrib.get("formatted") != "false":
            errors.append(f"{locale}: disclaimer literal percentage must disable formatting")

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
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{source}:{line}: hardcoded user-facing text: {value[:55]}")

if errors:
    print("Localization check FAILED: " + str(len(errors)) + " error(s)")
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"Localization check passed: {len(LOCALES)} locales, string keys, plural forms, placeholders, voice alerts, and direct Compose literals.")
