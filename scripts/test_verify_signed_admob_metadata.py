"""Regression tests for compiled APK AdMob/Billing metadata representations."""
import unittest

from verify_signed_admob_metadata import (
    APP_ID,
    ADMOB_METADATA_NAME,
    BILLING_METADATA_NAME,
    verify_signed_apk_admob_metadata,
)


RESOURCE_ID = "0x7f120001"
RESOURCES_DUMP = f"resource {RESOURCE_ID} string/admob_app_id\n  () \"{APP_ID}\"\n"


def manifest(admob_value: str, billing_value: str = "9.1.0") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <meta-data android:name="{ADMOB_METADATA_NAME}" android:value="{admob_value}" />
    <meta-data android:name="{BILLING_METADATA_NAME}" android:value="{billing_value}" />
  </application>
</manifest>
"""


class SignedAdMobMetadataTests(unittest.TestCase):
    def verify(self, value: str, resources: str = RESOURCES_DUMP, resolved: str = APP_ID,
               billing: str = "9.1.0") -> None:
        verify_signed_apk_admob_metadata(manifest(value, billing), resources, resolved)

    def test_symbolic_resource_reference(self) -> None:
        self.verify("@string/admob_app_id")

    def test_typed_hex_resource_reference(self) -> None:
        self.verify("@0x7f120001")

    def test_hex_resource_reference_without_0x_prefix(self) -> None:
        self.verify("@7F120001")

    def test_bare_hex_resource_reference(self) -> None:
        self.verify("0x7f120001")

    def test_direct_approved_app_id(self) -> None:
        self.verify(APP_ID)

    def test_rejects_reference_to_a_different_resource(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not reference"):
            self.verify("@0x7f120002")

    def test_rejects_wrong_resolved_admob_app_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.verify("@string/admob_app_id", resolved="ca-app-pub-0000000000000000~0000000000")

    def test_rejects_missing_or_duplicate_admob_metadata(self) -> None:
        xml = manifest("@string/admob_app_id").replace(
            "</application>",
            f'<meta-data xmlns:android="http://schemas.android.com/apk/res/android" '
            f'android:name="{ADMOB_METADATA_NAME}" android:value="@string/admob_app_id" />'
            "</application>",
        )
        with self.assertRaisesRegex(ValueError, "exactly one manifest metadata"):
            verify_signed_apk_admob_metadata(xml, RESOURCES_DUMP, APP_ID)

    def test_rejects_wrong_billing_version(self) -> None:
        with self.assertRaisesRegex(ValueError, "Billing metadata must be 9.1.0"):
            self.verify("@string/admob_app_id", billing="8.0.0")

    def test_rejects_duplicate_resource_ids(self) -> None:
        dump = RESOURCES_DUMP + "resource 0x7f120002 string/admob_app_id\n"
        with self.assertRaisesRegex(ValueError, "exactly one admob_app_id"):
            self.verify("@string/admob_app_id", resources=dump)


if __name__ == "__main__":
    unittest.main()
