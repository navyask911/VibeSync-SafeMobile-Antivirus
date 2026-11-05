#!/usr/bin/env python3
"""Publish privacy-safe aggregate threat-intelligence metrics for the public dashboard.

Hybrid Analysis requests are made once by enrich_threats.py earlier in this cron
run. This script reuses that run's hash input and the local reputation cache so
the metrics step does not spend a second provider request or exceed quotas.

Cloudflare metrics are read from a dedicated KV namespace. The Android client
only submits hashes for ScanVerdict.THREAT results, so one unique SHA-256
contribution key represents one accepted, confirmed-threat donation.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Mapping
from urllib.parse import quote

import requests

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
DEFAULT_WORKER_URL = "https://misty-fog-d936.navyask911.workers.dev"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z", re.IGNORECASE)
SHA256_KEY_RE = re.compile(r"(?:^|[:/])([0-9a-f]{64})\Z", re.IGNORECASE)
CLOUDFLARE_PAGE_SIZE = 1000
CLOUDFLARE_MAX_KEY_PAGES = 1000

DONATION_ALIASES = {
    "cloudflare_total_donations", "total_donations", "totaldonations",
    "donations", "donation_count", "donationcount",
    "total_contributions", "totalcontributions", "contributions",
    "contribution_count", "contributioncount",
}
THREAT_ALIASES = {
    "cloudflare_confirmed_threats", "confirmed_threats", "confirmedthreats",
    "confirmed_threat_count", "confirmedthreatcount",
    "total_confirmed_threats", "totalconfirmedthreats",
    "malicious_samples", "malicioussamples", "total_threats", "totalthreats",
}


class MetricsError(RuntimeError):
    """A required metrics source could not be read or validated."""


def _non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise MetricsError(f"{label} must be a non-negative integer.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdigit():
        number = int(value.strip())
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    else:
        raise MetricsError(f"{label} must be a non-negative integer.")
    if number < 0:
        raise MetricsError(f"{label} must be a non-negative integer.")
    return number


def _close_response(response: Any) -> None:
    close = getattr(response, "close", None)
    if callable(close):
        close()


def read_current_feed_hashes(path: Path) -> set[str]:
    """Read the TweetFeed hash list built during this workflow execution."""
    if not path.is_file():
        raise MetricsError(f"Current-run TweetFeed hash list is missing: {path}")
    hashes: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
        digest = raw.strip().lower()
        if not digest:
            continue
        if not SHA256_RE.fullmatch(digest):
            raise MetricsError(f"Invalid SHA-256 at {path}:{line_number}.")
        hashes.add(digest)
    return hashes

def tweetfeed_current_sha256_count(path: Path) -> int:
    """Count unique SHA-256 IOCs from this run's already-validated TweetFeed feed."""
    return len(read_current_feed_hashes(path))


def hybrid_analysis_verified_count(
    hashes_path: Path,
    cache_path: Path,
    api_key: str,
) -> int:
    """Count current-feed hashes that HA marked malicious with score >= 70.

    The API key is required to ensure the preceding enrichment step was
    configured. No additional HA request is made here: enrich_threats.py
    already queried the provider with quota enforcement and stored the result.
    """
    if not api_key.strip():
        raise MetricsError("HYBRID_ANALYSIS_API_KEY is not configured.")
    current_hashes = read_current_feed_hashes(hashes_path)
    if not cache_path.is_file():
        raise MetricsError(f"Hybrid Analysis cache from the current workflow is missing: {cache_path}")

    verified: set[str] = set()
    with cache_path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        required = {"sha256", "ha_threat_score", "ha_verdict"}
        if not required.issubset(set(reader.fieldnames or [])):
            raise MetricsError("Hybrid Analysis cache is missing required columns.")

        for row in reader:
            digest = (row.get("sha256") or "").strip().lower()
            if digest not in current_hashes or digest in verified:
                continue
            verdict = (row.get("ha_verdict") or "").strip().lower()
            score_text = (row.get("ha_threat_score") or "").strip()
            score: float | None = None
            if score_text:
                try:
                    score = float(score_text)
                except (TypeError, ValueError):
                    score = None
            if verdict == "malicious" and (score is None or score >= 70):
                verified.add(digest)
    return len(verified)


def _walk_json(value: Any):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield str(key).strip().lower().replace("-", "_"), nested
            yield from _walk_json(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_json(nested)


def parse_cloudflare_metrics_document(payload: Any) -> tuple[int, int] | None:
    """Read donation/threat counters from a KV aggregate JSON document."""
    if not isinstance(payload, (dict, list)):
        return None
    found: dict[str, int] = {}
    for key, value in _walk_json(payload):
        normalized = key.replace("_", "")
        if normalized in {name.replace("_", "") for name in DONATION_ALIASES}:
            try:
                found["donations"] = _non_negative_int(value, "Cloudflare donations")
            except MetricsError:
                continue
        elif normalized in {name.replace("_", "") for name in THREAT_ALIASES}:
            try:
                found["threats"] = _non_negative_int(value, "Cloudflare confirmed threats")
            except MetricsError:
                continue
    if "donations" in found and "threats" in found:
        return found["donations"], found["threats"]
    if "donations" in found:
        # The app's fixed Worker endpoint is called only after a confirmed
        # ScanVerdict.THREAT; this namespace is dedicated to those donations.
        return found["donations"], found["donations"]
    if "threats" in found:
        return found["threats"], found["threats"]
    return None


def count_sha256_kv_keys(keys: list[dict[str, Any]]) -> int:
    """Count unique SHA-256 contribution records in a dedicated KV namespace."""
    hashes: set[str] = set()
    for item in keys:
        name = item.get("name") if isinstance(item, dict) else None
        if not isinstance(name, str):
            continue
        match = SHA256_KEY_RE.search(name)
        if match:
            hashes.add(match.group(1).lower())
    return len(hashes)


class CloudflareKVReader:
    """Read-only Cloudflare KV client; never logs or returns the API token."""

    AGGREGATE_KEYS = (
        "dashboard_metrics",
        "dashboard-metrics",
        "global_threat_intelligence_stats",
        "global-threat-intelligence-stats",
        "threat_intelligence_stats",
        "threat-intelligence-stats",
        "contribution_stats",
        "contribution-stats",
        "stats",
        "metrics",
        "totals",
    )
    DONATION_KEYS = (
        "total_donations",
        "totalDonations",
        "donation_count",
        "total_contributions",
        "contribution_count",
    )
    THREAT_KEYS = (
        "confirmed_threats",
        "confirmedThreats",
        "confirmed_threat_count",
        "total_confirmed_threats",
        "malicious_samples",
    )

    def __init__(
        self,
        api_token: str,
        *,
        account_id: str = "",
        namespace_id: str = "",
        namespace_title: str = "",
        session: Any | None = None,
        sleep=time.sleep,
    ):
        if not api_token.strip():
            raise MetricsError("CLOUDFLARE_API_TOKEN is not configured.")
        self.session = session or requests.Session()
        self.sleep = sleep
        self.headers = {
            "Authorization": f"Bearer {api_token.strip()}",
            "Accept": "application/json",
        }
        self.account_id = account_id.strip()
        self.namespace_id = namespace_id.strip()
        self.namespace_title = namespace_title.strip()

    def _request(self, url: str, *, params: dict[str, Any] | None = None, allow_404: bool = False):
        response = None
        for attempt in range(3):
            response = self.session.get(
                url,
                headers=self.headers,
                params=params,
                timeout=(10, 30),
            )
            if response.status_code not in (429, 500, 502, 503, 504):
                break
            retry_after = getattr(response, "headers", {}).get("Retry-After")
            try:
                delay = float(retry_after) if retry_after is not None else 2 ** (attempt + 1)
            except (TypeError, ValueError):
                delay = 2 ** (attempt + 1)
            _close_response(response)
            if attempt == 2:
                raise MetricsError(f"Cloudflare API remained unavailable (HTTP {response.status_code}).")
            self.sleep(min(max(delay, 1.0), 30.0))
        assert response is not None
        if response.status_code == 404 and allow_404:
            _close_response(response)
            return None
        try:
            response.raise_for_status()
            return response
        except requests.RequestException as error:
            _close_response(response)
            raise MetricsError(f"Cloudflare API request failed (HTTP {response.status_code}).") from error

    def _json(self, url: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self._request(url, params=params)
        try:
            try:
                payload = response.json()
            except (ValueError, TypeError) as error:
                raise MetricsError("Cloudflare API returned invalid JSON.") from error
        finally:
            _close_response(response)
        if not isinstance(payload, dict) or payload.get("success") is False:
            raise MetricsError("Cloudflare API reported an unsuccessful response.")
        return payload

    def _account(self) -> str:
        if self.account_id:
            return self.account_id
        payload = self._json(f"{CLOUDFLARE_API_BASE}/accounts", params={"per_page": 50})
        accounts = payload.get("result")
        if not isinstance(accounts, list) or not accounts:
            raise MetricsError("Cloudflare token cannot discover an account; set CLOUDFLARE_ACCOUNT_ID.")
        if len(accounts) != 1:
            raise MetricsError("Multiple Cloudflare accounts found; set CLOUDFLARE_ACCOUNT_ID.")
        account_id = accounts[0].get("id") if isinstance(accounts[0], dict) else None
        if not isinstance(account_id, str) or not account_id:
            raise MetricsError("Cloudflare account response omitted its ID.")
        self.account_id = account_id
        return account_id

    def _namespace(self) -> str:
        if self.namespace_id:
            return self.namespace_id
        account_id = self._account()
        payload = self._json(
            f"{CLOUDFLARE_API_BASE}/accounts/{quote(account_id, safe='')}/storage/kv/namespaces",
            params={"per_page": 100},
        )
        namespaces = payload.get("result")
        if not isinstance(namespaces, list):
            raise MetricsError("Cloudflare KV namespace listing is invalid.")
        if self.namespace_title:
            matches = [
                item for item in namespaces
                if isinstance(item, dict)
                and str(item.get("title", "")).casefold() == self.namespace_title.casefold()
            ]
        else:
            keywords = ("safemobile", "safe-mobile", "threat", "intelligence", "donation", "contribution")
            matches = [
                item for item in namespaces
                if isinstance(item, dict)
                and any(word in str(item.get("title", "")).casefold() for word in keywords)
            ]
        if len(matches) != 1:
            raise MetricsError(
                "Could not identify one dedicated SafeMobile threat-contribution KV namespace; "
                "set CLOUDFLARE_KV_NAMESPACE_ID or CLOUDFLARE_KV_NAMESPACE_TITLE."
            )
        namespace_id = matches[0].get("id")
        if not isinstance(namespace_id, str) or not namespace_id:
            raise MetricsError("Cloudflare KV namespace response omitted its ID.")
        self.namespace_id = namespace_id
        return namespace_id

    def _value(self, account_id: str, namespace_id: str, key: str) -> str | None:
        url = (
            f"{CLOUDFLARE_API_BASE}/accounts/{quote(account_id, safe='')}"
            f"/storage/kv/namespaces/{quote(namespace_id, safe='')}/values/{quote(key, safe='')}"
        )
        response = self._request(url, allow_404=True)
        if response is None:
            return None
        try:
            return response.text.strip()
        finally:
            _close_response(response)

    def _keys(self, account_id: str, namespace_id: str) -> list[dict[str, Any]]:
        url = (
            f"{CLOUDFLARE_API_BASE}/accounts/{quote(account_id, safe='')}"
            f"/storage/kv/namespaces/{quote(namespace_id, safe='')}/keys"
        )
        keys: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(CLOUDFLARE_MAX_KEY_PAGES):
            params: dict[str, Any] = {"limit": CLOUDFLARE_PAGE_SIZE}
            if cursor:
                params["cursor"] = cursor
            payload = self._json(url, params=params)
            page = payload.get("result")
            if not isinstance(page, list):
                raise MetricsError("Cloudflare KV key listing is invalid.")
            keys.extend(item for item in page if isinstance(item, dict))
            result_info = payload.get("result_info")
            next_cursor = result_info.get("cursor") if isinstance(result_info, dict) else None
            if not next_cursor:
                return keys
            cursor = str(next_cursor)
        raise MetricsError("Cloudflare KV key listing exceeded the safety page limit.")

    def fetch_counts(self) -> tuple[int, int]:
        account_id = self._account()
        namespace_id = self._namespace()

        aggregate_keys = list(self.AGGREGATE_KEYS)
        configured_key = os.environ.get("CLOUDFLARE_KV_METRICS_KEY", "").strip()
        if configured_key:
            aggregate_keys.insert(0, configured_key)

        for key in dict.fromkeys(aggregate_keys):
            raw = self._value(account_id, namespace_id, key)
            if not raw:
                continue
            try:
                document = json.loads(raw)
            except json.JSONDecodeError:
                continue
            metrics = parse_cloudflare_metrics_document(document)
            if metrics is not None:
                return metrics

        donation_count: int | None = None
        threat_count: int | None = None
        for key in self.DONATION_KEYS:
            raw = self._value(account_id, namespace_id, key)
            if raw is not None:
                try:
                    donation_count = _non_negative_int(raw, "Cloudflare donation count")
                    break
                except MetricsError:
                    try:
                        donation_count = parse_cloudflare_metrics_document(json.loads(raw))[0]
                        break
                    except (ValueError, TypeError, MetricsError):
                        pass
        for key in self.THREAT_KEYS:
            raw = self._value(account_id, namespace_id, key)
            if raw is not None:
                try:
                    threat_count = _non_negative_int(raw, "Cloudflare confirmed-threat count")
                    break
                except MetricsError:
                    try:
                        parsed = parse_cloudflare_metrics_document(json.loads(raw))
                        if parsed is not None:
                            threat_count = parsed[1]
                            break
                    except (ValueError, TypeError, MetricsError):
                        pass
        if donation_count is not None and threat_count is not None:
            return donation_count, threat_count
        if donation_count is not None:
            # SafeMobile's fixed contribution endpoint accepts only confirmed THREAT results.
            return donation_count, donation_count
        if threat_count is not None:
            return threat_count, threat_count

        # Some deployments store one KV entry per donated SHA-256 instead of a
        # compact aggregate. Count only hash-shaped keys in the dedicated
        # contribution namespace; never infer counts from arbitrary KV keys.
        contribution_count = count_sha256_kv_keys(self._keys(account_id, namespace_id))
        if contribution_count:
            return contribution_count, contribution_count
        raise MetricsError(
            "Cloudflare contribution totals were not found. Publish a JSON aggregate "
            "under dashboard_metrics (or set CLOUDFLARE_KV_METRICS_KEY), or store "
            "one SHA-256-keyed entry per contribution in the dedicated namespace."
        )


def next_six_hour_fetch(now: datetime) -> datetime:
    """Return exactly six hours after the UTC metrics-fetch timestamp."""
    fetched_at = now.astimezone(timezone.utc).replace(microsecond=0)
    return fetched_at + timedelta(hours=6)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_metrics(path: Path, metrics: dict[str, Any]) -> None:
    required = {
        "last_fetched", "next_fetch", "tweetfeed_count", "ha_verified_count",
        "cloudflare_total_donations", "cloudflare_confirmed_threats",
    }
    if set(metrics) != required:
        raise MetricsError("Dashboard metrics payload does not match the public JSON contract.")
    for key in required - {"last_fetched", "next_fetch"}:
        metrics[key] = _non_negative_int(metrics[key], key)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(metrics, indent=2, sort_keys=False, allow_nan=False) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def read_last_known_metrics(path: Path) -> dict[str, Any]:
    """Read a previous public snapshot for per-source failure fallback."""
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"WARNING: Previous dashboard metrics could not be read ({error}); "
            "safe zero defaults will be used where sources fail.",
            file=sys.stderr,
        )
        return {}
    if not isinstance(payload, dict):
        print(
            "WARNING: Previous dashboard metrics are not a JSON object; "
            "safe zero defaults will be used where sources fail.",
            file=sys.stderr,
        )
        return {}
    return payload


def _last_known_count(previous: Mapping[str, Any] | None, field: str) -> int:
    """Return a validated previous count or zero; never return null."""
    if previous is not None and field in previous:
        try:
            return _non_negative_int(previous[field], field)
        except MetricsError:
            pass
    print(
        f"WARNING: No valid last-known-good value for {field}; using safe default 0.",
        file=sys.stderr,
    )
    return 0


def _warn_source_fallback(label: str, error: Exception, field: str) -> None:
    print(
        f"WARNING: {label} metrics unavailable ({error}); retaining the last "
        f"known-good {field} value or using 0.",
        file=sys.stderr,
    )


def build_metrics(
    *,
    ha_api_key: str,
    cloudflare_api_token: str,
    hashes_path: Path = Path("data/new_hashes.txt"),
    ha_cache_path: Path = Path("data/enriched_threats.csv"),
    cloudflare_reader: CloudflareKVReader | None = None,
    now: datetime | None = None,
    fallback_metrics: Mapping[str, Any] | None = None,
    ha_enrichment_succeeded: bool = True,
) -> dict[str, Any]:
    """Build the exact public contract, falling back independently per source."""
    fetched_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    next_fetch = next_six_hour_fetch(fetched_at)

    try:
        tweetfeed_count = _non_negative_int(
            tweetfeed_current_sha256_count(hashes_path),
            "TweetFeed current-feed SHA-256 count",
        )
    except (MetricsError, requests.RequestException, OSError, ValueError) as error:
        _warn_source_fallback("TweetFeed", error, "tweetfeed_count")
        tweetfeed_count = _last_known_count(fallback_metrics, "tweetfeed_count")

    try:
        if not ha_enrichment_succeeded:
            raise MetricsError(
                "the current workflow's Hybrid Analysis enrichment step failed; "
                "avoiding a partial current-feed count"
            )
        ha_count = _non_negative_int(
            hybrid_analysis_verified_count(hashes_path, ha_cache_path, ha_api_key),
            "Hybrid Analysis verified count",
        )
    except (MetricsError, requests.RequestException, OSError, ValueError, csv.Error) as error:
        _warn_source_fallback("Hybrid Analysis", error, "ha_verified_count")
        ha_count = _last_known_count(fallback_metrics, "ha_verified_count")

    try:
        cf_reader = cloudflare_reader or CloudflareKVReader(cloudflare_api_token)
        donation_count, threat_count = cf_reader.fetch_counts()
        donation_count = _non_negative_int(donation_count, "Cloudflare total donations")
        threat_count = _non_negative_int(threat_count, "Cloudflare confirmed threats")
    except (MetricsError, requests.RequestException, OSError, ValueError) as error:
        _warn_source_fallback("Cloudflare KV", error, "cloudflare donation/threat counts")
        donation_count = _last_known_count(fallback_metrics, "cloudflare_total_donations")
        threat_count = _last_known_count(fallback_metrics, "cloudflare_confirmed_threats")

    return {
        "last_fetched": iso_utc(fetched_at),
        "next_fetch": iso_utc(next_fetch),
        "tweetfeed_count": tweetfeed_count,
        "ha_verified_count": ha_count,
        "cloudflare_total_donations": donation_count,
        "cloudflare_confirmed_threats": threat_count,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/dashboard_metrics.json"))
    parser.add_argument("--hashes", type=Path, default=Path("data/new_hashes.txt"))
    parser.add_argument("--ha-cache", type=Path, default=Path("data/enriched_threats.csv"))
    args = parser.parse_args()

    ha_api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
    cloudflare_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    ha_enrichment_succeeded = os.environ.get("HA_ENRICHMENT_SUCCEEDED", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }
    try:
        previous_metrics = read_last_known_metrics(args.output)
        metrics = build_metrics(
            ha_api_key=ha_api_key,
            cloudflare_api_token=cloudflare_token,
            hashes_path=args.hashes,
            ha_cache_path=args.ha_cache,
            fallback_metrics=previous_metrics,
            ha_enrichment_succeeded=ha_enrichment_succeeded,
        )
        write_metrics(args.output, metrics)
    except (MetricsError, OSError, requests.RequestException) as error:
        print(f"Dashboard metrics generation failed safely: {error}", file=sys.stderr)
        return 1

    print(
        "Dashboard metrics refreshed: "
        f"TweetFeed today SHA-256={metrics['tweetfeed_count']}, "
        f"HA verified malicious={metrics['ha_verified_count']}, "
        f"Cloudflare donations={metrics['cloudflare_total_donations']}, "
        f"Cloudflare confirmed threats={metrics['cloudflare_confirmed_threats']}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
