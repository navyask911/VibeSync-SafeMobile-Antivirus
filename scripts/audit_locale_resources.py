#!/usr/bin/env python3
"""Audit Android values resources across every localized values-* directory.

Reports missing translatable baseline IDs, missing resource files, duplicate
string/plurals/string-array IDs across all XML files in each locale, malformed
XML, unescaped Android string apostrophes, and format/plural-shape drift.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

RESOURCE_ROOT = Path("app/src/main/res")
RESOURCE_TAGS = {"string", "plurals", "string-array"}
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[sdif]")
XML_FILES = re.compile(r"^values(?:-[^/]+)?$")


def parse_file(path: Path):
    root = ET.parse(path).getroot()
    found = []
    for element in root.iter():
        if element.tag not in RESOURCE_TAGS or not element.get("name"):
            continue
        found.append(element)
    return found


def identity(element):
    return (element.tag, element.get("name"))


def placeholders(element):
    return sorted(PLACEHOLDER.findall("".join(element.itertext())))


def plural_categories(element):
    if element.tag != "plurals":
        return None
    return sorted(item.get("quantity", "") for item in element.findall("item"))


def text_segments(element):
    if element.text:
        yield element.text
    for child in list(element):
        yield from text_segments(child)
        if child.tail:
            yield child.tail


def unescaped_apostrophe(element):
    return any(re.search(r"(?<!\\)'", segment) for segment in text_segments(element))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--strict", action="store_true",
                        help="fail if any baseline translatable resource is missing")
    args = parser.parse_args()

    default_dir = RESOURCE_ROOT / "values"
    if not default_dir.is_dir():
        raise SystemExit(f"Missing baseline resource directory: {default_dir}")

    baseline = {}
    baseline_files = {}
    for path in sorted(default_dir.glob("*.xml")):
        try:
            entries = parse_file(path)
        except ET.ParseError as exc:
            raise SystemExit(f"Malformed baseline XML {path}: {exc}")
        for entry in entries:
            if entry.get("translatable", "true").lower() == "false":
                continue
            key = identity(entry)
            if key in baseline:
                raise SystemExit(f"Duplicate baseline resource {key}: {baseline_files[key]} and {path}")
            baseline[key] = entry
            baseline_files[key] = path.name

    locale_dirs = sorted(
        p for p in RESOURCE_ROOT.iterdir()
        if p.is_dir() and p.name.startswith("values-") and p.name != "values-v31"
    )
    locale_summaries = []
    all_duplicate_ids = []
    all_bad_apostrophes = []
    all_format_mismatches = []
    total_missing = 0
    total_missing_files = 0

    for locale_dir in locale_dirs:
        definitions = defaultdict(list)
        files_present = {p.name for p in locale_dir.glob("*.xml")}
        locale_xml = sorted(locale_dir.glob("*.xml"))

        for path in locale_xml:
            try:
                entries = parse_file(path)
            except ET.ParseError as exc:
                raise SystemExit(f"Malformed XML {path}: {exc}")
            for entry in entries:
                key = identity(entry)
                definitions[key].append((path.name, entry))
                if entry.tag == "string" and unescaped_apostrophe(entry):
                    all_bad_apostrophes.append({
                        "locale": locale_dir.name,
                        "file": path.name,
                        "name": entry.get("name"),
                    })

        for key, values in definitions.items():
            if len(values) > 1:
                all_duplicate_ids.append({
                    "locale": locale_dir.name,
                    "type": key[0],
                    "name": key[1],
                    "files": [file_name for file_name, _ in values],
                })

        missing = sorted(
            key for key in baseline
            if not any(entry.get("translatable", "true").lower() != "false"
                       for _, entry in definitions.get(key, []))
        )
        total_missing += len(missing)

        format_mismatches = []
        for key in sorted(set(baseline).intersection(definitions)):
            expected = placeholders(baseline[key])
            for file_name, entry in definitions[key]:
                actual = placeholders(entry)
                if expected != actual:
                    format_mismatches.append({
                        "type": key[0], "name": key[1], "file": file_name,
                        "expected": expected, "actual": actual,
                    })
                expected_plural = plural_categories(baseline[key])
                actual_plural = plural_categories(entry)
                if expected_plural is not None and expected_plural != actual_plural:
                    format_mismatches.append({
                        "type": key[0], "name": key[1], "file": file_name,
                        "expected_plural_categories": expected_plural,
                        "actual_plural_categories": actual_plural,
                    })
        all_format_mismatches.extend(
            {"locale": locale_dir.name, **item} for item in format_mismatches
        )

        # A resource file is considered missing only when it is absent and none
        # of that file's baseline IDs are defined in any other locale XML file.
        missing_files = []
        for base_file in sorted(set(baseline_files.values())):
            if base_file in files_present:
                continue
            file_keys = [key for key, name in baseline_files.items() if name == base_file]
            if any(definitions.get(key) for key in file_keys):
                continue
            missing_files.append(base_file)
        total_missing_files += len(missing_files)

        locale_summaries.append({
            "locale": locale_dir.name,
            "xml_files": len(locale_xml),
            "missing_baseline_ids": len(missing),
            "missing_ids": [f"{kind}/{name}" for kind, name in missing],
            "missing_baseline_files": missing_files,
            "duplicate_ids": sum(1 for item in all_duplicate_ids
                                 if item["locale"] == locale_dir.name),
            "unescaped_apostrophes": sum(1 for item in all_bad_apostrophes
                                         if item["locale"] == locale_dir.name),
            "format_or_plural_mismatches": len(format_mismatches),
        })

    report = {
        "locale_count": len(locale_dirs),
        "baseline_translatable_ids": len(baseline),
        "missing_baseline_ids_total": total_missing,
        "missing_baseline_files_total": total_missing_files,
        "duplicate_ids_total": len(all_duplicate_ids),
        "unescaped_apostrophes_total": len(all_bad_apostrophes),
        "format_or_plural_mismatches_total": len(all_format_mismatches),
        "duplicates": all_duplicate_ids,
        "unescaped_apostrophes": all_bad_apostrophes,
        "format_or_plural_mismatches": all_format_mismatches,
        "locales": locale_summaries,
    }
    Path("build").mkdir(exist_ok=True)
    Path("build/locale-resource-audit.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\\n", encoding="utf-8"
    )
    print(
        f"Locale resource audit: {len(locale_dirs)} locales; "
        f"{len(baseline)} baseline IDs; {total_missing} missing IDs; "
        f"{total_missing_files} missing baseline files; "
        f"{len(all_duplicate_ids)} duplicates; "
        f"{len(all_bad_apostrophes)} unescaped apostrophes; "
        f"{len(all_format_mismatches)} format/plural mismatches."
    )
    for item in locale_summaries:
        print(
            f"{item['locale']}: files={item['xml_files']} "
            f"missing_ids={item['missing_baseline_ids']} "
            f"missing_files={len(item['missing_baseline_files'])} "
            f"duplicates={item['duplicate_ids']} "
            f"apostrophes={item['unescaped_apostrophes']} "
            f"format_mismatches={item['format_or_plural_mismatches']}"
        )
    if all_duplicate_ids:
        print("DUPLICATES: " + json.dumps(all_duplicate_ids, ensure_ascii=False))
    if all_bad_apostrophes:
        print("UNESCAPED_APOSTROPHES: " + json.dumps(all_bad_apostrophes, ensure_ascii=False))
    if all_format_mismatches:
        print("FORMAT_MISMATCHES: " + json.dumps(all_format_mismatches, ensure_ascii=False))

    fatal = bool(all_duplicate_ids or all_bad_apostrophes or all_format_mismatches)
    if args.strict and (fatal or total_missing or total_missing_files):
        fatal = True
    if fatal:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
