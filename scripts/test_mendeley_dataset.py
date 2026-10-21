#!/usr/bin/env python3
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from mendeley_dataset import DatasetError, extract_safely, import_manifest, validate_zip


class MendeleyDatasetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_zip(self, members):
        path = self.root / "fixture.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in members.items():
                archive.writestr(name, value)
        return path

    def test_extracts_and_indexes_research_records_without_discarding_duplicates(self):
        h1, h2 = "a" * 64, "b" * 64
        csv_text = "\n".join([
            "sha256,label,family,train,test",
            f"{h1},malware,Trojan,true,false",
            f"{h2},goodware,Benign,false,true",
            f"{h1},malware,Trojan,true,false",
            "invalid-hash,malware,Unknown,false,false",
        ]) + "\n"
        archive = self.make_zip({"research/manifest.csv": csv_text, "research/README.txt": "fixture"})
        stats = validate_zip(archive)
        self.assertEqual("research/manifest.csv", stats["manifest_member"])
        output = self.root / "extracted"
        extracted = extract_safely(archive, output, "fixture-sha256")
        db = output / "research-index.sqlite3"
        result = import_manifest(output / extracted["manifest_relative_path"], db)
        self.assertEqual(4, result["rows_examined"])
        self.assertEqual(3, result["valid_sha256_rows"])
        self.assertEqual(1, result["invalid_hash_rows"])
        self.assertEqual(1, result["duplicate_hash_rows_after_first"])
        self.assertEqual(2, result["unique_sha256_hashes"])
        self.assertEqual("sha256", result["hash_column"])
        self.assertEqual("label", result["label_column"])
        self.assertTrue(result["research_labels_not_verified_live_indicators"])
        with sqlite3.connect(db) as connection:
            row_count = connection.execute("SELECT COUNT(*) FROM research_hashes").fetchone()[0]
            split_json = connection.execute(
                "SELECT split_values_json FROM research_hashes WHERE row_number=2"
            ).fetchone()[0]
        self.assertEqual(4, row_count)
        self.assertEqual({"train": "true", "test": "false"}, json.loads(split_json))

    def test_rejects_path_traversal_before_extract(self):
        archive = self.make_zip({
            "../outside.txt": "not allowed",
            "manifest.csv": "sha256,label\n" + ("c" * 64) + ",malware\n",
        })
        with self.assertRaises(DatasetError):
            validate_zip(archive)

    def test_requires_hash_and_label_columns(self):
        path = self.root / "manifest.csv"
        path.write_text("filename,family\napp.apk,Trojan\n", encoding="utf-8")
        with self.assertRaises(DatasetError):
            import_manifest(path, self.root / "index.sqlite3")

    def test_explicit_column_names_are_normalized(self):
        path = self.root / "manifest.csv"
        path.write_text("SHA-256 Hash,Binary Label\n" + ("d" * 64) + ",malware\n", encoding="utf-8")
        result = import_manifest(path, self.root / "index.sqlite3",
                                 hash_column="sha256_hash", label_column="binary_label")
        self.assertEqual(1, result["valid_sha256_rows"])
        self.assertEqual("SHA-256 Hash", result["hash_column"])
        self.assertEqual("Binary Label", result["label_column"])


if __name__ == "__main__":
    unittest.main()
