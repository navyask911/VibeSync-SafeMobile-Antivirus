"""Network-free tests for VirusTotal and Hybrid Analysis hash enrichment."""
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from enrich_threats import CSV_FIELDS, EnrichmentError, HA_URL, VT_URL, ReputationClient, enrich_hashes

HASH1 = "a" * 64
HASH2 = "b" * 64


class Response:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self.payload = payload or {}
        self.headers = headers or {}
        self.closed = False

    def json(self):
        return self.payload

    def close(self):
        self.closed = True

    def raise_for_status(self):
        raise RuntimeError(f"unexpected HTTP {self.status_code}")


class EnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.hashes = self.root / "new_hashes.txt"
        self.cache = self.root / "enriched_threats.csv"
        self.quota = self.root / "enrichment_quota.json"

    def env(self):
        return patch.dict("os.environ", {
            "VIRUSTOTAL_API_KEY": "vt-test-key",
            "HYBRID_ANALYSIS_API_KEY": "ha-test-key",
            "VIRUSTOTAL_COMMERCIAL_USE_APPROVED": "true",
        })

    def test_existing_hash_is_skipped_without_any_provider_request(self):
        self.hashes.write_text(HASH1 + "\n", encoding="ascii")
        with self.cache.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerow({"sha256": HASH1, "vt_malicious_count": 3,
                             "ha_threat_score": 80, "ha_verdict": "malicious"})
        session = Mock()
        with self.env():
            result = enrich_hashes(self.hashes, self.cache, self.quota, session=session)
        self.assertEqual(result["added"], 0)
        session.get.assert_not_called()
        session.post.assert_not_called()

    def test_hash_only_requests_parse_scores_and_record_404_as_not_found(self):
        self.hashes.write_text(f"{HASH1}\n{HASH2}\n", encoding="ascii")
        session = Mock()
        session.get.side_effect = [
            Response(payload={"data": {"attributes": {"last_analysis_stats": {"malicious": 11}}}}),
            Response(status_code=404),
        ]
        session.post.side_effect = [
            Response(payload=[{"sha256": HASH1, "threat_score": 88, "verdict": "malicious"}]),
            Response(status_code=404),
        ]
        with self.env(), patch("enrich_threats.time.sleep"):
            result = enrich_hashes(self.hashes, self.cache, self.quota, session=session)
        self.assertEqual(result["added"], 2)
        self.assertEqual(session.get.call_args_list[0].args[0], VT_URL.format(sha256=HASH1))
        self.assertEqual(session.get.call_args_list[0].kwargs["headers"]["x-apikey"], "vt-test-key")
        self.assertEqual(session.post.call_args_list[0].args[0], HA_URL)
        self.assertEqual(session.post.call_args_list[0].kwargs["headers"]["api-key"], "ha-test-key")
        self.assertEqual(session.post.call_args_list[0].kwargs["data"], {"hash": HASH1})
        self.assertNotIn("files", session.post.call_args_list[0].kwargs)
        with self.cache.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(rows[0]["vt_malicious_count"], "11")
        self.assertEqual(rows[0]["ha_threat_score"], "88")
        self.assertEqual(rows[0]["ha_verdict"], "malicious")
        self.assertEqual(rows[1]["vt_malicious_count"], "Not Found")
        self.assertEqual(rows[1]["ha_verdict"], "Not Found")
        self.assertTrue(self.quota.exists())

    def test_429_retries_with_exponential_backoff(self):
        session = Mock()
        session.get.side_effect = [
            Response(status_code=429, headers={"Retry-After": "1"}),
            Response(payload={"data": {"attributes": {"last_analysis_stats": {"malicious": 4}}}}),
        ]
        sleeper = Mock()
        client = ReputationClient(session, self.quota, sleep=sleeper, monotonic=lambda: 100.0)
        self.assertEqual(client.virustotal_malicious_count(HASH1, "vt-test-key"), 4)
        self.assertEqual(session.get.call_count, 2)
        self.assertGreaterEqual(sleeper.call_args_list[0].args[0], 30.0)

    def test_provider_spacing_is_enforced_between_requests(self):
        session = Mock()
        vt_payload = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}
        ha_payload = [{"sha256": HASH1, "threat_score": 55, "verdict": "malicious"}]
        session.get.side_effect = [Response(payload=vt_payload), Response(payload=vt_payload)]
        session.post.side_effect = [Response(payload=ha_payload), Response(payload=ha_payload)]
        now = [0.0]
        delays = []

        def clock():
            return now[0]

        def sleep(seconds):
            delays.append(seconds)
            now[0] += seconds

        client = ReputationClient(session, self.quota, sleep=sleep, monotonic=clock)
        client.virustotal_malicious_count(HASH1, "vt-key")
        client.virustotal_malicious_count(HASH2, "vt-key")
        client.hybrid_analysis_result(HASH1, "ha-key")
        client.hybrid_analysis_result(HASH2, "ha-key")
        self.assertIn(16.0, delays)
        self.assertIn(2.0, delays)

    def test_virus_total_commercial_gate_fails_before_network(self):
        self.hashes.write_text(HASH1 + "\n", encoding="ascii")
        session = Mock()
        with patch.dict("os.environ", {
            "VIRUSTOTAL_API_KEY": "vt-key",
            "HYBRID_ANALYSIS_API_KEY": "ha-key",
        }, clear=True):
            with self.assertRaisesRegex(EnrichmentError, "commercial business-workflow"):
                enrich_hashes(self.hashes, self.cache, self.quota, session=session)
        session.get.assert_not_called()
        session.post.assert_not_called()

    def test_invalid_hash_rejected_before_network(self):
        self.hashes.write_text("not-a-sha256\n", encoding="ascii")
        session = Mock()
        with self.assertRaises(EnrichmentError):
            enrich_hashes(self.hashes, self.cache, self.quota, session=session)
        session.get.assert_not_called()
        session.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
