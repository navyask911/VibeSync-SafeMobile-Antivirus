"""Offline tests for the public dashboard metrics generator."""
import csv
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from generate_dashboard_metrics import (
    MetricsError,
    count_sha256_kv_keys,
    hybrid_analysis_verified_count,
    next_six_hour_fetch,
    parse_cloudflare_metrics_document,
    tweetfeed_today_sha256_count,
    write_metrics,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.headers = {}
        self.text = ""
        self.closed = False

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        self.closed = True


class MetricsGeneratorTests(unittest.TestCase):
    def test_tweetfeed_reads_preaggregated_today_sha256_count(self):
        response = FakeResponse({
            "windows": {"today": {"types": {"sha256": 142}}}
        })
        session = Mock()
        session.get.return_value = response
        self.assertEqual(tweetfeed_today_sha256_count(session=session), 142)
        self.assertIn("/v1/counts", session.get.call_args.args[0])
        self.assertTrue(response.closed)

    def test_tweetfeed_rejects_missing_counter(self):
        session = Mock()
        session.get.return_value = FakeResponse({"windows": {"today": {"types": {}}})
        with self.assertRaises(MetricsError):
            tweetfeed_today_sha256_count(session=session)

    def test_ha_count_is_scoped_to_current_feed_and_confirmed_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = root / "new_hashes.txt"
            cache = root / "enriched.csv"
            hashes.write_text(f"{HASH_A}\n{HASH_B}\n{HASH_C}\n", encoding="ascii")
            with cache.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(
                    stream, fieldnames=("sha256", "vt_malicious_count", "ha_threat_score", "ha_verdict")
                )
                writer.writeheader()
                writer.writerows([
                    {"sha256": HASH_A, "ha_threat_score": "70", "ha_verdict": "malicious"},
                    {"sha256": HASH_B, "ha_threat_score": "69", "ha_verdict": "malicious"},
                    {"sha256": HASH_C, "ha_threat_score": "95", "ha_verdict": "clean"},
                    {"sha256": "d" * 64, "ha_threat_score": "99", "ha_verdict": "malicious"},
                ])
            self.assertEqual(hybrid_analysis_verified_count(hashes, cache, "configured-key"), 1)

    def test_ha_requires_secret_and_current_run_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = root / "missing.txt"
            cache = root / "cache.csv"
            with self.assertRaises(MetricsError):
                hybrid_analysis_verified_count(hashes, cache, "")
            with self.assertRaises(MetricsError):
                hybrid_analysis_verified_count(hashes, cache, "configured-key")

    def test_cloudflare_nested_aggregate_document(self):
        value = {
            "data": {
                "totals": {
                    "total_donations": "1420",
                    "confirmed_threats": 312,
                }
            }
        }
        self.assertEqual(parse_cloudflare_metrics_document(value), (1420, 312))

    def test_cloudflare_single_donation_counter_uses_confirmed_donation_contract(self):
        self.assertEqual(
            parse_cloudflare_metrics_document({"donation_count": 7}),
            (7, 7),
        )

    def test_count_only_unique_sha256_keys(self):
        keys = [
            {"name": HASH_A},
            {"name": f"donation:{HASH_B}"},
            {"name": f"sha256/{HASH_A}"},
            {"name": "dashboard_metrics"},
            {"name": "non-hash-key"},
        ]
        self.assertEqual(count_sha256_kv_keys(keys), 2)

    def test_next_six_hour_cron_boundary(self):
        value = datetime(2026, 11, 5, 12, 12, 44, tzinfo=timezone.utc)
        self.assertEqual(
            next_six_hour_fetch(value),
            datetime(2026, 11, 5, 18, 0, tzinfo=timezone.utc),
        )
        late = datetime(2026, 11, 5, 23, 59, tzinfo=timezone.utc)
        self.assertEqual(
            next_six_hour_fetch(late),
            datetime(2026, 11, 6, 0, 0, tzinfo=timezone.utc),
        )

    def test_metrics_writer_requires_exact_public_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metrics.json"
            payload = {
                "last_fetched": "2026-11-05T12:00:00Z",
                "next_fetch": "2026-11-05T18:00:00Z",
                "tweetfeed_count": 142,
                "ha_verified_count": 312,
                "cloudflare_total_donations": 1420,
                "cloudflare_confirmed_threats": 312,
            }
            write_metrics(path, payload)
            import json
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)


if __name__ == "__main__":
    unittest.main()
