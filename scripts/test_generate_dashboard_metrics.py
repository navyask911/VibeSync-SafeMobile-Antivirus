"""Offline tests for the public dashboard metrics generator."""
import csv
import io
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from generate_dashboard_metrics import (
    CloudflareKVReader,
    DEFAULT_CLOUDFLARE_KV_METRICS_KEY,
    MetricsError,
    hybrid_analysis_verified_count,
    next_six_hour_fetch,
    parse_cloudflare_metrics_document,
    tweetfeed_current_sha256_count,
    build_metrics,
    main,
    write_metrics,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=""):
        self._payload = payload
        self.status_code = status_code
        self.headers = {}
        self.text = text
        self.closed = False

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def close(self):
        self.closed = True


class MetricsGeneratorTests(unittest.TestCase):
    def test_tweetfeed_count_uses_validated_current_feed_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            hashes = Path(directory) / "new_hashes.txt"
            hashes.write_text(f"{HASH_A}\n{HASH_B}\n{HASH_A.upper()}\n", encoding="ascii")
            self.assertEqual(tweetfeed_current_sha256_count(hashes), 2)

    def test_tweetfeed_count_rejects_missing_current_feed(self):
        with tempfile.TemporaryDirectory() as directory:
            hashes = Path(directory) / "missing_hashes.txt"
            with self.assertRaises(MetricsError):
                tweetfeed_current_sha256_count(hashes)

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

    def test_ha_malicious_verdict_counts_when_score_is_not_supplied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hashes = root / "new_hashes.txt"
            cache = root / "enriched.csv"
            hashes.write_text(f"{HASH_A}\n", encoding="ascii")
            with cache.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(
                    stream, fieldnames=("sha256", "vt_malicious_count", "ha_threat_score", "ha_verdict")
                )
                writer.writeheader()
                writer.writerow({
                    "sha256": HASH_A,
                    "ha_threat_score": "Not Found",
                    "ha_verdict": "malicious",
                })
            self.assertEqual(hybrid_analysis_verified_count(hashes, cache, "configured-key"), 1)

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


    def test_cloudflare_default_key_is_safemobile_donation_totals(self):
        self.assertEqual(DEFAULT_CLOUDFLARE_KV_METRICS_KEY, "safemobile_donation_totals")
        session = Mock()
        session.get.return_value = FakeResponse(
            text='{"total_donations": 17, "confirmed_threats": 13, "private_note": "do-not-log"}'
        )
        output = io.StringIO()
        with patch.dict("os.environ", {}, clear=True), patch("sys.stdout", output):
            reader = CloudflareKVReader(
                "token",
                account_id="account",
                namespace_id="namespace",
                session=session,
            )
            self.assertEqual(reader.fetch_counts(), (17, 13))

        requested_url = session.get.call_args.args[0]
        self.assertTrue(requested_url.endswith("/values/safemobile_donation_totals"))
        self.assertIn("cloudflare_total_donations", output.getvalue())
        self.assertIn("17", output.getvalue())
        self.assertNotIn("private_note", output.getvalue())
        self.assertNotIn("do-not-log", output.getvalue())

    def test_cloudflare_metrics_key_is_fixed_even_when_environment_override_is_set(self):
        session = Mock()
        session.get.return_value = FakeResponse(
            text='{"data":{"totalDonations":"34","confirmedThreats":21}}'
        )
        output = io.StringIO()
        with (
            patch.dict("os.environ", {"CLOUDFLARE_KV_METRICS_KEY": "aggregate_stats"}),
            patch("sys.stdout", output),
        ):
            reader = CloudflareKVReader(
                "token",
                account_id="account",
                namespace_id="namespace",
                session=session,
            )
            self.assertEqual(reader.fetch_counts(), (34, 21))

        requested_url = session.get.call_args.args[0]
        self.assertTrue(requested_url.endswith("/values/safemobile_donation_totals"))
        self.assertNotIn("/values/aggregate_stats", requested_url)
        self.assertIn("'status': 'parsed'", output.getvalue())

    def test_cloudflare_debug_mode_shows_structure_and_counters_but_redacts_other_values(self):
        session = Mock()
        session.get.return_value = FakeResponse(
            text='{"data":{"totals":{"total_donations":17,"confirmed_threats":13},'
                 '"private_note":"do-not-log","worker_token":"secret-value"}}'
        )
        output = io.StringIO()
        with patch("sys.stdout", output):
            reader = CloudflareKVReader(
                "token",
                account_id="account",
                namespace_id="namespace",
                debug_cloudflare=True,
                session=session,
            )
            self.assertEqual(reader.fetch_counts(), (17, 13))

        logged = output.getvalue()
        self.assertIn("DEBUG: Raw Cloudflare KV Response (redacted):", logged)
        self.assertIn('"total_donations":17', logged)
        self.assertIn('"confirmed_threats":13', logged)
        self.assertNotIn("do-not-log", logged)
        self.assertNotIn("secret-value", logged)

    def test_cloudflare_empty_null_and_missing_values_return_zero(self):
        for response_body in ("", "null", "{}", "[]"):
            with self.subTest(response_body=response_body):
                session = Mock()
                session.get.return_value = FakeResponse(text=response_body)
                output = io.StringIO()
                with patch.dict("os.environ", {}, clear=True), patch("sys.stdout", output):
                    reader = CloudflareKVReader(
                        "token",
                        account_id="account",
                        namespace_id="namespace",
                        session=session,
                    )
                    self.assertEqual(reader.fetch_counts(), (0, 0))

                self.assertIn("Cloudflare KV Response (redacted)", output.getvalue())
                self.assertEqual(session.get.call_count, 1)

        missing_session = Mock()
        missing_session.get.return_value = FakeResponse(status_code=404)
        warning = io.StringIO()
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("sys.stdout", io.StringIO()),
            patch("sys.stderr", warning),
        ):
            missing_reader = CloudflareKVReader(
                "token",
                account_id="account",
                namespace_id="namespace",
                session=missing_session,
            )
            self.assertEqual(missing_reader.fetch_counts(), (0, 0))
        self.assertIn(
            "Cloudflare KV key 'safemobile_donation_totals' not found. Returning 0.",
            warning.getvalue(),
        )

    def test_cloudflare_invalid_json_returns_zero_without_raising(self):
        session = Mock()
        session.get.return_value = FakeResponse(text="this is not JSON")
        with (
            patch.dict("os.environ", {}, clear=True),
            patch("sys.stdout", io.StringIO()),
            patch("sys.stderr", io.StringIO()),
        ):
            reader = CloudflareKVReader(
                "token",
                account_id="account",
                namespace_id="namespace",
                session=session,
            )
            self.assertEqual(reader.fetch_counts(), (0, 0))

    def test_next_fetch_is_exactly_six_hours_after_last_fetched(self):
        value = datetime(2026, 11, 5, 12, 12, 44, tzinfo=timezone.utc)
        self.assertEqual(
            next_six_hour_fetch(value),
            datetime(2026, 11, 5, 18, 12, 44, tzinfo=timezone.utc),
        )
        late = datetime(2026, 11, 5, 23, 59, tzinfo=timezone.utc)
        self.assertEqual(
            next_six_hour_fetch(late),
            datetime(2026, 11, 6, 5, 59, tzinfo=timezone.utc),
        )

    def test_build_metrics_preserves_last_known_counts_when_sources_fail(self):
        previous = {
            "last_fetched": "2026-11-05T06:00:00Z",
            "next_fetch": "2026-11-05T12:00:00Z",
            "tweetfeed_count": 142,
            "ha_verified_count": 312,
            "cloudflare_total_donations": 1420,
            "cloudflare_confirmed_threats": 312,
        }

        class FailingCloudflareReader:
            def fetch_counts(self):
                raise MetricsError("Cloudflare token or namespace is unavailable")

        with patch(
            "generate_dashboard_metrics.tweetfeed_current_sha256_count",
            side_effect=MetricsError("TweetFeed temporarily unavailable"),
        ):
            result = build_metrics(
                ha_api_key="configured",
                cloudflare_api_token="configured",
                cloudflare_reader=FailingCloudflareReader(),
                fallback_metrics=previous,
                ha_enrichment_succeeded=False,
                now=datetime(2026, 11, 5, 7, 30, 0, tzinfo=timezone.utc),
            )

        self.assertEqual(
            set(result),
            {
                "last_fetched", "next_fetch", "tweetfeed_count", "ha_verified_count",
                "cloudflare_total_donations", "cloudflare_confirmed_threats",
            },
        )
        self.assertEqual(result["last_fetched"], "2026-11-05T07:30:00Z")
        self.assertEqual(result["next_fetch"], "2026-11-05T13:30:00Z")
        self.assertEqual(result["tweetfeed_count"], 142)
        self.assertEqual(result["ha_verified_count"], 312)
        self.assertEqual(result["cloudflare_total_donations"], 1420)
        self.assertEqual(result["cloudflare_confirmed_threats"], 312)
        self.assertNotIn(None, result.values())

    def test_build_metrics_uses_safe_zero_defaults_without_previous_snapshot(self):
        class FailingCloudflareReader:
            def fetch_counts(self):
                raise MetricsError("Cloudflare unavailable")

        with patch(
            "generate_dashboard_metrics.tweetfeed_current_sha256_count",
            side_effect=MetricsError("TweetFeed unavailable"),
        ):
            result = build_metrics(
                ha_api_key="",
                cloudflare_api_token="",
                cloudflare_reader=FailingCloudflareReader(),
                fallback_metrics=None,
                ha_enrichment_succeeded=False,
                now=datetime(2026, 11, 5, 7, 30, 0, tzinfo=timezone.utc),
            )

        for field in (
            "tweetfeed_count", "ha_verified_count",
            "cloudflare_total_donations", "cloudflare_confirmed_threats",
        ):
            self.assertEqual(result[field], 0)
            self.assertIsNotNone(result[field])


    def test_missing_cloudflare_namespace_warns_and_skips_query_with_zero_counts(self):
        previous = {
            "cloudflare_total_donations": 88,
            "cloudflare_confirmed_threats": 22,
        }
        stderr = io.StringIO()
        with (
            patch("generate_dashboard_metrics.tweetfeed_current_sha256_count", return_value=21),
            patch("generate_dashboard_metrics.hybrid_analysis_verified_count", return_value=5),
            patch("generate_dashboard_metrics.CloudflareKVReader") as reader_factory,
            patch("sys.stderr", stderr),
        ):
            result = build_metrics(
                ha_api_key="configured-ha-key",
                cloudflare_api_token="configured-cloudflare-token",
                cloudflare_account_id="secret-account-id",
                cloudflare_namespace_id="",
                fallback_metrics=previous,
                now=datetime(2026, 11, 5, 8, 0, 0, tzinfo=timezone.utc),
            )

        reader_factory.assert_not_called()
        self.assertEqual(result["tweetfeed_count"], 21)
        self.assertEqual(result["ha_verified_count"], 5)
        self.assertEqual(result["cloudflare_total_donations"], 0)
        self.assertEqual(result["cloudflare_confirmed_threats"], 0)
        self.assertIn("CLOUDFLARE_KV_NAMESPACE_ID is missing", stderr.getvalue())

    def test_main_reads_cloudflare_account_id_from_environment_secret(self):
        expected_metrics = {
            "last_fetched": "2026-11-05T08:00:00Z",
            "next_fetch": "2026-11-05T14:00:00Z",
            "tweetfeed_count": 21,
            "ha_verified_count": 5,
            "cloudflare_total_donations": 0,
            "cloudflare_confirmed_threats": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dashboard_metrics.json"
            with (
                patch.dict(
                    "os.environ",
                    {
                        "HYBRID_ANALYSIS_API_KEY": "ha-key",
                        "CLOUDFLARE_API_TOKEN": "cf-token",
                        "CLOUDFLARE_ACCOUNT_ID": "account-from-secret",
                        "CLOUDFLARE_KV_NAMESPACE_ID": "namespace-id",
                        "CLOUDFLARE_KV_NAMESPACE_TITLE": "SafeMobile Contributions",
                    },
                ),
                patch("sys.argv", [
                    "generate_dashboard_metrics.py", "--output", str(output), "--debug-cloudflare"
                ]),
                patch("generate_dashboard_metrics.read_last_known_metrics", return_value={}),
                patch("generate_dashboard_metrics.build_metrics", return_value=expected_metrics) as build,
                patch("generate_dashboard_metrics.write_metrics"),
                patch("sys.stdout", io.StringIO()),
            ):
                self.assertEqual(main(), 0)

        kwargs = build.call_args.kwargs
        self.assertEqual(kwargs["cloudflare_account_id"], "account-from-secret")
        self.assertEqual(kwargs["cloudflare_namespace_id"], "namespace-id")
        self.assertEqual(kwargs["cloudflare_namespace_title"], "SafeMobile Contributions")
        self.assertTrue(kwargs["debug_cloudflare"])

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
