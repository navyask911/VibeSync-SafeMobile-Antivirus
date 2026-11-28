"""Verify signed APK AdMob metadata from its compiled manifest and resource table."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

APP_ID = "ca-app-pub-4783826505860771~3262295335"
BILLING_VERSION = "9.1.0"
ADMOB_METADATA_NAME = "com.google.android.gms.ads.APPLICATION_ID"
BILLING_METADATA_NAME = "com.google.android.play.billingclient.version"


def _local_name(name: str) -> str:
    return name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _attribute(element: ET.Element, expected_name: str) -> str:
    values = [
        value for name, value in element.attrib.items()
        if _local_name(name) == expected_name
    ]
    if len(values) != 1:
        raise ValueError(f"Expected exactly one {expected_name!r} attribute.")
    return values[0].strip()


def _metadata_element(application: ET.Element, metadata_name: str) -> ET.Element:
    matches = []
    for child in list(application):
        if _local_name(child.tag) == "meta-data" and _attribute(child, "name") == metadata_name:
            matches.append(child)
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one manifest metadata entry for {metadata_name!r}; "
            f"found {len(matches)}."
        )
    return matches[0]


def _admob_resource_id(resources_dump: str) -> int:
    matches = re.findall(
        r"(?m)^\s*resource\s+(0x[0-9a-fA-F]{8})\s+string/admob_app_id\b",
        resources_dump,
    )
    resource_ids = {int(value, 16) for value in matches}
    if len(resource_ids) != 1:
        raise ValueError("The APK must contain exactly one admob_app_id resource-table ID.")
    return next(iter(resource_ids))


def _parse_resource_reference(value: str) -> int:
    token = value.strip()
    if token.startswith("@"):
        token = token[1:]
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,8}", token):
        return int(token[2:], 16)
    if re.fullmatch(r"[0-9]{1,10}", token):
        return int(token, 10)
    if re.fullmatch(r"[0-9a-fA-F]{8}", token) and re.search(r"[a-fA-F]", token):
        return int(token, 16)
    raise ValueError("AAPT2 compiled manifest AdMob value is not a typed resource reference.")


def _compiled_admob_resource_reference(compiled_manifest_tree: str) -> int:
    """Read the typed android:value from the unique AdMob meta-data block in AAPT2 xmltree."""
    lines = compiled_manifest_tree.splitlines()
    matching_blocks = []
    for index, line in enumerate(lines):
        element = re.match(r"^(\s*)E:\s+meta-data(?:\s|$)", line)
        if not element:
            continue
        indent = len(element.group(1))
        end = len(lines)
        for next_index in range(index + 1, len(lines)):
            next_element = re.match(r"^(\s*)E:\s+", lines[next_index])
            if next_element and len(next_element.group(1)) <= indent:
                end = next_index
                break
        block = lines[index + 1:end]
        names = []
        for entry in block:
            match = re.search(r'\bandroid:name(?:\([^)]*\))?="([^"]+)"', entry)
            if match:
                names.append(match.group(1))
        if ADMOB_METADATA_NAME in names:
            matching_blocks.append(block)

    if len(matching_blocks) != 1:
        raise ValueError(
            "AAPT2 compiled manifest must contain exactly one AdMob APPLICATION_ID "
            f"meta-data node; found {len(matching_blocks)}."
        )
    values = []
    for entry in matching_blocks[0]:
        match = re.search(r"\bandroid:value(?:\([^)]*\))?=(\S+)", entry)
        if match:
            values.append(match.group(1))
    if len(values) != 1:
        raise ValueError("AAPT2 compiled AdMob meta-data must contain exactly one android:value.")
    return _parse_resource_reference(values[0])


def verify_signed_apk_admob_metadata(
    manifest_xml: str,
    resources_dump: str,
    admob_resource_value: str,
    compiled_manifest_tree: str,
) -> None:
    """Verify metadata uniqueness, Billing version, AdMob resource ID and resolved value."""
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError as error:
        raise ValueError(f"Signed APK manifest XML is invalid: {error}") from error
    if _local_name(root.tag) != "manifest":
        raise ValueError("Signed APK manifest root element is missing.")
    applications = [child for child in list(root) if _local_name(child.tag) == "application"]
    if len(applications) != 1:
        raise ValueError(f"Expected exactly one application element; found {len(applications)}.")
    application = applications[0]

    # APK Analyzer text formatting is not trusted for the resource ID. It only
    # establishes unique metadata names; AAPT2 xmltree supplies the compiled ID.
    admob_entry = _metadata_element(application, ADMOB_METADATA_NAME)
    _attribute(admob_entry, "value")
    billing_entry = _metadata_element(application, BILLING_METADATA_NAME)
    if _attribute(billing_entry, "value") != BILLING_VERSION:
        raise ValueError(f"Signed APK Google Play Billing metadata must be {BILLING_VERSION}.")

    resource_id = _admob_resource_id(resources_dump)
    compiled_reference_id = _compiled_admob_resource_reference(compiled_manifest_tree)
    if compiled_reference_id != resource_id:
        raise ValueError(
            "Signed APK AdMob metadata resource reference "
            f"0x{compiled_reference_id:08x} does not match the "
            f"admob_app_id resource-table ID 0x{resource_id:08x}."
        )

    resolved_value = admob_resource_value.strip().strip('"').strip("'")
    if resolved_value != APP_ID:
        raise ValueError(
            "Signed APK admob_app_id resource does not match the approved production App ID."
        )
