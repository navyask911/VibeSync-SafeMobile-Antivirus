"""Offline fixtures for ThreatFox SHA-256 parsing and bounded hash conversion."""
import gzip
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

from build_threatfox_hsb import (
    API_URL, InputRejected, convert, fetch_recent_iocs, sha256_iocs,
)

HASH1 = "a" * 64
HASH2 = "B" * 64


class ThreatFoxHashExportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "hashes.hsb"

    def write(self, data: bytes, kind: str = "plain"):
        path = self.root / "download"
        if kind == "zip":
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr("sha256.txt", data)
        elif kind == "gzip":
            path.write_bytes(gzip.compress(data))
        else:
            path.write_bytes(data)
        return path

    def test_fetch_uses_documented_threatfox_auth_and_payload(self):
        response = MagicMock()
        response.content = b'{"query_status":"ok","data":[]}'
        response.json.return_value = {"query_status": "ok", "data": []}
        response.__enter__.return_value = response
        session = MagicMock()
        session.post.return_value = response

        payload = fetch_recent_iocs("test-auth-key", 1, session=session)

        self.assertEqual(payload["query_status"], "ok")
        args, kwargs = session.post.call_args
        self.assertEqual(args[0], API_URL)
        self.assertEqual(kwargs["headers"]["Auth-Key"], "test-auth-key")
        self.assertEqual(kwargs["json"], {"query": "get_iocs", "days": 1})
        self.assertFalse(kwargs["allow_redirects"])

    def test_parser_extracts_only_sha256_iocs_and_deduplicates(self):
        payload = {
            "query_status": "ok",
            "data": [
                {"ioc_type": "domain", "ioc": "bad.example"},
                {"ioc_type": "sha256_hash", "ioc": HASH1},
                {"ioc_type": "sha256_hash", "ioc": HASH2},
                {"ioc_type": "sha256_hash", "ioc": HASH1.upper()},
                {"ioc_type": "url", "ioc": "https://example.invalid/file"},
            ],
        }
        self.assertEqual(sha256_iocs(payload), [HASH1, HASH2.lower()])

    def test_parser_rejects_malformed_sha256_ioc_and_empty_sha256_set(self):
        with self.assertRaisesRegex(InputRejected, "malformed"):
            sha256_iocs({"query_status": "ok", "data": [
                {"ioc_type": "sha256_hash", "ioc": "../bad"}
            ]})
        with self.assertRaisesRegex(InputRejected, "no valid sha256_hash"):
            sha256_iocs({"query_status": "ok", "data": [
                {"ioc_type": "domain", "ioc": "example.invalid"}
            ]})

    def test_plain_zip_gzip_conversion_with_threatfox_source_and_label(self):
        data = f"# ThreatFox SHA-256 IOCs\n{HASH1}\n{HASH2}\n".encode()
        for kind in ("plain", "zip", "gzip"):
            with self.subTest(kind=kind):
                report = convert(self.write(data, kind), self.out, 42, "ApprovedTF-2026",
                                 date="2026-11-05T00:00:00Z")
                self.assertEqual(report["records"], 2)
                content = self.out.read_text()
                self.assertTrue(content.startswith(
                    "# SAFEHASH version=42 source=threatfox.abuse.ch license=ApprovedTF-2026\n"))
                self.assertIn("# VERSION: 1\n# DATE: 2026-11-05T00:00:00Z\n", content)
                self.assertEqual(content.count("ThreatFox.SHA256\n"), 2)

    def test_optional_hashes_output_matches_normalized_hsb_records(self):
        source = self.write(f"# feed\n{HASH1}\n{HASH2}\n".encode())
        hashes_output = self.root / "data" / "new_hashes.txt"
        report = convert(source, self.out, 19, "ApprovedTF", hashes_output=hashes_output)
        self.assertEqual(report["records"], 2)
        self.assertEqual(hashes_output.read_text(encoding="ascii"), f"{HASH1}\n{HASH2.lower()}\n")
        self.assertIn(f"{HASH1}:ThreatFox.SHA256\n", self.out.read_text())
        self.assertIn(f"{HASH2.lower()}:ThreatFox.SHA256\n", self.out.read_text())

    def test_reject_nonhash_duplicate_and_empty_data(self):
        for data in (
            b"<html>HTTP 429</html>\n",
            f"{HASH1}\n{HASH1}\n".encode(),
            b"# only comments\n",
        ):
            with self.subTest(data=data[:15]):
                with self.assertRaises(InputRejected):
                    convert(self.write(data), self.out, 17, "ApprovedTF")

    def test_refuses_truncation_and_size_overrun(self):
        source = self.write(f"{HASH1}\n{HASH2}\n".encode())
        with self.assertRaisesRegex(InputRejected, "Do not truncate"):
            convert(source, self.out, 18, "ApprovedTF", max_records=1)
        self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(InputRejected, "Do not truncate"):
            convert(source, self.out, 18, "ApprovedTF", max_bytes=130)

    def test_requires_permission_reference_and_positive_version(self):
        source = self.write(f"{HASH1}\n".encode())
        for invalid in ("", "CC BY", "bad:token"):
            with self.assertRaises(InputRejected):
                convert(source, self.out, 1, invalid)
        with self.assertRaises(InputRejected):
            convert(source, self.out, 0, "ApprovedTF")

    def test_rejects_ambiguous_zip(self):
        path = self.root / "download"
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("first.txt", HASH1)
            z.writestr("second.txt", HASH2)
        with self.assertRaises(InputRejected):
            convert(path, self.out, 8, "ApprovedTF")


if __name__ == "__main__":
    unittest.main()
