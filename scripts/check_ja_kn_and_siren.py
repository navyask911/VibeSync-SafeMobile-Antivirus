#!/usr/bin/env python3
"""Regression gates for user-visible Kannada/Japanese strings and siren test isolation."""
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

root = Path(__file__).resolve().parents[1]
res = root / "app/src/main/res"
ANDROID = "{http://schemas.android.com/apk/res/android}"
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[sdif]")

def strings(path):
    doc = ET.parse(path).getroot()
    return {entry.attrib["name"]: "".join(entry.itertext())
            for entry in doc.findall("string")}

errors = []
manifest = ET.parse(root / "app/src/main/AndroidManifest.xml").getroot()
receiver = manifest.find(f'.//receiver[@{ANDROID}name=".core.observer.PackageInstallReceiver"]')
if receiver is None or receiver.get(ANDROID + "exported") != "true":
    errors.append("Install receiver must be enabled and exported for protected system package events")
else:
    action_names = {a.get(ANDROID + "name") for a in receiver.findall("./intent-filter/action")}
    schemes = {s.get(ANDROID + "scheme") for s in receiver.findall("./intent-filter/data")}
    if action_names != {"android.intent.action.PACKAGE_ADDED", "android.intent.action.PACKAGE_REPLACED"}:
        errors.append(f"Install receiver actions differ: {action_names}")
    if schemes != {"package"}:
        errors.append(f"Install receiver does not filter package: scheme: {schemes}")
perms = {p.get(ANDROID + "name") for p in manifest.findall("uses-permission")}
for p in ("android.permission.POST_NOTIFICATIONS",
          "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"):
    if p not in perms: errors.append(f"Permission missing: {p}")
activity = manifest.find(f'.//activity[@{ANDROID}name=".core.observer.ThreatDetectedActivity"]')
if activity is None or activity.get(ANDROID + "exported") != "false":
    errors.append("ThreatDetectedActivity must remain non-exported")

files = ("strings.xml", "device_posture.xml", "incident_response.xml",
         "sentinel_security.xml", "system_app_protection.xml",
         "detection_capabilities.xml", "siren_diagnostics.xml")
# All user-facing resources must be translatable so Kannada/Japanese override lookup works.
for file in files:
    default_xml = ET.parse(res / "values" / file).getroot()
    forbidden = [x.attrib["name"] for x in default_xml.findall("string")
                 if x.attrib.get("translatable") == "false" and not x.attrib["name"].startswith("locale_")]
    if forbidden:
        errors.append(f"Untranslatable UI strings in {file}: {', '.join(forbidden)}")

for lang in ("kn", "ja"):
    for file in files:
        source = strings(res / "values" / file)
        target_file = res / f"values-{lang}" / file
        if not target_file.exists():
            errors.append(f"Missing {lang} translation resource: {file}")
            continue
        target = strings(target_file)
        missing = sorted(source.keys() - target.keys())
        if missing: errors.append(f"{lang}/{file} missing: {', '.join(missing)}")
        for key, value in source.items():
            if key in target and sorted(PLACEHOLDER.findall(value)) != sorted(PLACEHOLDER.findall(target[key])):
                errors.append(f"{lang}/{file}/{key} has format placeholder mismatch")

    source = strings(res / "values/strings.xml")
    target = strings(res / f"values-{lang}/strings.xml")
    for key in ("brand_title", "nav_home", "nav_scan", "nav_apps",
                "nav_analytics", "nav_settings"):
        if target.get(key) == source.get(key):
            errors.append(f"Untranslated primary navigation: {lang}/{key}")
    src_warning = strings(res / "values/device_posture.xml")["posture_dashboard_warning"]
    translated_warning = strings(res / f"values-{lang}/device_posture.xml").get("posture_dashboard_warning", "")
    if not translated_warning or translated_warning == src_warning:
        errors.append(f"Loophole banner must be translated in {lang}")

if errors:
    print("\n".join(errors), file=sys.stderr)
    sys.exit(1)
print("Siren receiver contract and Kannada/Japanese navigation, posture, incident and alert translations verified.")
