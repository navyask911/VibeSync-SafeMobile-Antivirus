"""Offline tests for public TweetFeed fetching and SAFEHASH conversion."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from build_tweetfeed_hsb import (
    API_URL,
    InputRejected,
    build_database,
    fetch_feed,
    sha256_values,
)

HASH1 = "a" * 64
HASH2 = "b" * 64


class FakeResponse:
    def __init__(self, payload, *, status_code=200, headers=None):
        self.payload = payload
        self.content = json.dumps(payload).encode("utf-8")
        self.status_code = status_code
        self.headers = headers or {}
        self.closed = False

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        self.closed = True


class TweetFeedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / "hashes.hsb"

    def test_fetches_public_endpoint_without_any_api_key(self):
        response = FakeResponse([{"type": "sha256", "value": HASH1}])
        session = Mock()
        session.get.return_value = response

        records = fetch_feed(session=session)

        self.assertEqual(records, [{"type": "sha256", "value": HASH1}])
        args, kwargs = session.get.call_args
        self.assertEqual(args[0], API_URL)
        self.assertEqual(API_URL, "https://api.tweetfeed.live/v1/week/malware/sha256")
        self.assertNotIn("Authorization", kwargs["headers"])
        self.assertNotIn("Auth-Key", kwargs["headers"])
        self.assertEqual(kwargs["allow_redirects"], False)
        self.assertTrue(response.closed)

    def test_rejects_truncated_response(self):
        response = FakeResponse(
            [{"type": "sha256", "value": HASH1}],
            headers={"X-Result-Truncated": "true"},
        )
        with self.assertRaisesRegex(InputRejected, "truncated"):
            fetch_feed(session=Mock(get=Mock(return_value=response)))

    def test_extracts_only_sha256_values_and_deduplicates_case_insensitively(self):
        records = [
            {"type": "domain", "value": "malware.example"},
            {"type": "sha256", "value": HASH1},
            {"type": "sha256", "value": HASH2.upper()},
            {"type": "sha256", "value": HASH1.upper()},
            {"type": "url", "value": "https://example.invalid/payload"},
        ]
        self.assertEqual(sha256_values(records), [HASH1, HASH2])

    def test_rejects_invalid_sha256_value_and_empty_hash_feed(self):
        with self.assertRaisesRegex(InputRejected, "malformed"):
            sha256_values([{"type": "sha256", "value": "../bad"}])
        with self.assertRaisesRegex(InputRejected, "no usable SHA-256"):
            sha256_values([{"type": "domain", "value": "malware.example"}])

    def test_builds_cc0_tweetfeed_safehash_with_review_label(self):
        result = build_database(
            [HASH1, HASH2.upper(), HASH1],
            self.out,
            42,
            date="2026-11-05T00:00:00Z",
        )
        content = self.out.read_text(encoding="ascii")
        self.assertEqual(result["records"], 2)
        self.assertTrue(content.startswith(
            "# SAFEHASH version=42 source=tweetfeed.live license=CC0-1.0\n"
        ))
        self.assertIn("# VERSION: 1\n# DATE: 2026-11-05T00:00:00Z\n", content)
        self.assertEqual(content.count("TweetFeed.CommunityIOC\n"), 2)
        self.assertIn(f"{HASH1}:TweetFeed.CommunityIOC\n", content)

    def test_refuses_empty_malformed_and_oversized_inputs(self):
        for hashes in ([], ["not-a-hash"]):
            with self.subTest(hashes=hashes):
                with self.assertRaises(InputRejected):
                    build_database(hashes, self.out, 1)
        with self.assertRaisesRegex(InputRejected, "Do not truncate"):
            build_database([HASH1, HASH2], self.out, 7, max_records=1)
        self.assertFalse(self.out.exists())

    def test_requires_positive_monotonic_version_and_respects_size_limit(self):
        with self.assertRaises(InputRejected):
            build_database([HASH1], self.out, 0)
        with self.assertRaisesRegex(InputRejected, "Do not truncate"):
            build_database([HASH1], self.out, 7, max_bytes=100)


if __name__ == "__main__":
    unittest.main()
