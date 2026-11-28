"""Regression tests for AAPT2 compiled AdMob manifest references."""
import unittest

from verify_signed_admob_metadata import (
    APP_ID,
    ADMOB_METADATA_NAME,
    BILLING_METADATA_NAME,
    verify_signed_apk_admob_metadata,
)

RESOURCE_ID = "0x7f120001"
RESOURCE_ID_DECIMAL = str(int(RESOURCE_ID, 16))
RESOURCES_DUMP = f'resource {RESOURCE_ID} string/admob_app_id\n  () "{APP_ID}"\n'


def manifest(billing_value: str = "9.1.0") -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application>
    <meta-data android:name="{ADMOB_METADATA_NAME}" android:value="@string/admob_app_id" />
    <meta-data android:name="{BILLING_METADATA_NAME}" android:value="{billing_value}" />
  </application>
</manifest>
"""


def compiled_tree(admob_value: str = "@0x7f120001") -> str:
    return f"""N: android=http://schemas.android.com/apk/res/android
E: manifest (line=2)
  E: application (line=5)
    E: meta-data (line=8)
      A: android:name(0x01010003)="{ADMOB_METADATA_NAME}" (Raw: "{ADMOB_METADATA_NAME}")
      A: android:value(0x01010024)={admob_value} (Raw: "@string/admob_app_id")
    E: meta-data (line=11)
      A: android:name(0x01010003)="{BILLING_METADATA_NAME}" (Raw: "{BILLING_METADATA_NAME}")
      A: android:value(0x01010024)="9.1.0" (Raw: "9.1.0")
"""


class SignedAdMobMetadataTests(unittest.TestCase):
    def verify(
        self,
        tree_value: str = "@0x7f120001",
        resources: str = RESOURCES_DUMP,
        resolved: str = APP_ID,
        tree: str | None = None,
    ) -> None:
        verify_signed_apk_admob_metadata(
            manifest(),
            resources,
            resolved,
            compiled_tree(tree_value) if tree is None else tree,
        )

    def test_compiled_hex_resource_reference(self) -> None:
        self.verify("@0x7f120001")

    def test_compiled_decimal_resource_reference(self) -> None:
        self.verify("@" + RESOURCE_ID_DECIMAL)

    def test_compiled_hex_without_prefix(self) -> None:
        self.verify("@7f120001")

    def test_compiled_decimal_without_at_prefix(self) -> None:
        self.verify(RESOURCE_ID_DECIMAL)

    def test_rejects_reference_to_different_resource(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.verify("@0x7f120002")

    def test_rejects_literal_app_id_instead_of_resource_reference(self) -> None:
        with self.assertRaisesRegex(ValueError, "not a typed resource reference"):
            self.verify(APP_ID)

    def test_rejects_wrong_resolved_app_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match the approved"):
            self.verify(resolved="ca-app-pub-0000000000000000~0000000000")

    def test_rejects_wrong_billing_version(self) -> None:
        xml = manifest(billing_value="8.0.0")
        with self.assertRaisesRegex(ValueError, "Billing metadata must be 9.1.0"):
            verify_signed_apk_admob_metadata(xml, RESOURCES_DUMP, APP_ID, compiled_tree())

    def test_rejects_missing_or_duplicate_admob_metadata(self) -> None:
        xml = manifest().replace(
            "</application>",
            f'<meta-data xmlns:android="http://schemas.android.com/apk/res/android" '
            f'android:name="{ADMOB_METADATA_NAME}" android:value="@string/admob_app_id" />'
            "</application>",
        )
        with self.assertRaisesRegex(ValueError, "exactly one manifest metadata"):
            verify_signed_apk_admob_metadata(xml, RESOURCES_DUMP, APP_ID, compiled_tree())

    def test_rejects_duplicate_compiled_admob_nodes(self) -> None:
        duplicate = (
            '    E: meta-data (line=14)\n'
            f'      A: android:name(0x01010003)="{ADMOB_METADATA_NAME}"\n'
            '      A: android:value(0x01010024)=@0x7f120001\n'
        )
        with self.assertRaisesRegex(ValueError, "exactly one AdMob"):
            self.verify(tree=compiled_tree() + duplicate)

    def test_rejects_duplicate_resource_table_ids(self) -> None:
        dump = RESOURCES_DUMP + "resource 0x7f120002 string/admob_app_id\n"
        with self.assertRaisesRegex(ValueError, "exactly one admob_app_id"):
            self.verify(resources=dump)

    def test_rejects_missing_compiled_value(self) -> None:
        missing = compiled_tree().replace(
            '      A: android:value(0x01010024)=@0x7f120001 (Raw: "@string/admob_app_id")\n',
            "",
        )
        with self.assertRaisesRegex(ValueError, "exactly one android:value"):
            self.verify(tree=missing)


if __name__ == "__main__":
    unittest.main()
