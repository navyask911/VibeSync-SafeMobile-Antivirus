"""Strict verifier for the signed APK's AdMob and Play Billing manifest metadata.

The manifest may encode android:value as a symbolic resource name or as a numeric
resource-table reference. Every accepted representation is bound to the unique
admob_app_id resource and its approved production value.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET


APP_ID = "ca-app-pub-4783826505860771~3262295335"
BILLING_VERSION = "9.1.0"
ADMOB_METADATA_NAME = "com.google.android.gms.ads.APPLICATION_ID"
BILLING_METADATA_NAME = "com.google.android.play.billingclient.version"


def _local_name(name: str) -> str:
    """Return an XML element/attribute local name regardless of namespace prefix."""
    return name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _attribute(element: ET.Element, expected_name: str) -> str:
    values = [
        value for name, value in element.attrib.items()
        if _local_name(name) == expected_name
    ]
    if len(values) != 1:
        raise ValueError(f"Expected exactly one {expected_name!r} attribute.")
    return values[0].strip()


def _metadata_value(application: ET.Element, metadata_name: str) -> str:
    matches: list[ET.Element] = []
    for child in list(application):
        if _local_name(child.tag) != "meta-data":
            continue
        if _attribute(child, "name") == metadata_name:
            matches.append(child)
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one manifest metadata entry for {metadata_name!r}; "
            f"found {len(matches)}."
        )
    return _attribute(matches[0], "value")


def _admob_resource_id(resources_dump: str) -> int:
    matches = re.findall(
        r"(?m)^\s*resource\s+(0x[0-9a-fA-F]{8})\s+string/admob_app_id\b",
        resources_dump,
    )
    resource_ids = {int(value, 16) for value in matches}
    if len(resource_ids) != 1:
        raise ValueError(
            "The APK must contain exactly one admob_app_id resource-table ID."
        )
    return next(iter(resource_ids))


def _verify_admob_reference(metadata_value: str, resource_id: int) -> None:
    value = metadata_value.strip()
    if value in (APP_ID, "@string/admob_app_id"):
        return

    # APK Analyzer/AAPT2 versions may print typed resource references as
    # @0x7f......, @7f......, 0x7f......, or the bare eight-digit ID. Accept
    # only an eight-digit reference, then compare it to the APK's resource table.
    numeric_reference = re.fullmatch(r"@?(?:0[xX])?([0-9a-fA-F]{8})", value)
    if numeric_reference and int(numeric_reference.group(1), 16) == resource_id:
        return

    raise ValueError(
        "Signed APK AdMob metadata does not reference the approved admob_app_id resource."
    )


def verify_signed_apk_admob_metadata(
    manifest_xml: str,
    resources_dump: str,
    admob_resource_value: str,
) -> None:
    """Verify unique AdMob/Billing metadata and bind the APK reference to exact ID."""
    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError as error:
        raise ValueError(f"Signed APK manifest XML is invalid: {error}") from error
    if _local_name(root.tag) != "manifest":
        raise ValueError("Signed APK manifest root element is missing.")

    applications = [
        child for child in list(root)
        if _local_name(child.tag) == "application"
    ]
    if len(applications) != 1:
        raise ValueError(
            f"Expected exactly one application element; found {len(applications)}."
        )
    application = applications[0]

    admob_value = _metadata_value(application, ADMOB_METADATA_NAME)
    billing_value = _metadata_value(application, BILLING_METADATA_NAME)
    if billing_value != BILLING_VERSION:
        raise ValueError(
            f"Signed APK Google Play Billing metadata must be {BILLING_VERSION}."
        )

    resource_id = _admob_resource_id(resources_dump)
    resolved_value = admob_resource_value.strip().strip('"').strip("'")
    if resolved_value != APP_ID:
        raise ValueError(
            "Signed APK admob_app_id resource does not match the approved production App ID."
        )
    _verify_admob_reference(admob_value, resource_id)
