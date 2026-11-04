#!/usr/bin/env python3
"""Hash-only VirusTotal and Hybrid Analysis enrichment for ThreatFox SHA-256 IOCs.

The ThreatFox builder supplies a normalized SHA-256 text file. This module only
queries the optional reputation providers; it does not fetch ThreatFox IOCs or
upload APK, archive, file bytes, or samples to either reputation provider.
"""
from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import time
from typing import Any

import requests

CSV_FIELDS = ("sha256", "vt_malicious_count", "ha_threat_score", "ha_verdict")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
VT_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
HA_URL = "https://www.hybrid-analysis.com/api/v2/search/hash"
VT_INTERVAL_SECONDS = 16.0
VT_DAILY_LIMIT = 480  # VirusTotal Public API is documented at 4/minute and 500/day.
HA_INTERVAL_SECONDS = 2.0
HA_DAILY_LIMIT = 100
MAX_429_RETRIES = 5
BACKOFF_BASE_SECONDS = 30.0
BACKOFF_MAX_SECONDS = 900.0
USER_AGENT = "SafeMobile-Threat-Intelligence/1.0"


class EnrichmentError(RuntimeError):
    """Provider response or local enrichment state was invalid."""


class DailyQuotaReached(EnrichmentError):
    """Persistent UTC-day budget for a provider has been exhausted."""


def utc_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    try:
        temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def load_quota_state(path: Path) -> dict[str, Any]:
    today = utc_date()
    if not path.exists():
        return {"utc_date": today, "virustotal_requests": 0, "hybrid_analysis_requests": 0}
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EnrichmentError("Quota state is unreadable; refusing to reset provider counters.") from error
    if not isinstance(state, dict):
        raise EnrichmentError("Quota state must be a JSON object.")
    if state.get("utc_date") != today:
        return {"utc_date": today, "virustotal_requests": 0, "hybrid_analysis_requests": 0}
    for field in ("virustotal_requests", "hybrid_analysis_requests"):
        if type(state.get(field, 0)) is not int or state.get(field, 0) < 0:
            raise EnrichmentError("Quota state contains an invalid request counter.")
    return state


class ReputationClient:
    def __init__(self, session: requests.Session, quota_path: Path, *, sleep=None, monotonic=None):
        self.session = session
        self.quota_path = quota_path
        self.sleep = sleep or time.sleep
        self.monotonic = monotonic or time.monotonic
        self.usage = load_quota_state(quota_path)
        self.last_request_at: dict[str, float] = {}

    @staticmethod
    def _counter(provider: str) -> str:
        return "virustotal_requests" if provider == "virustotal" else "hybrid_analysis_requests"

    @staticmethod
    def _interval(provider: str) -> float:
        return VT_INTERVAL_SECONDS if provider == "virustotal" else HA_INTERVAL_SECONDS

    @staticmethod
    def _limit(provider: str) -> int:
        return VT_DAILY_LIMIT if provider == "virustotal" else HA_DAILY_LIMIT

    def ensure_budget(self, provider: str) -> None:
        count = self.usage[self._counter(provider)]
        if count >= self._limit(provider):
            raise DailyQuotaReached(
                f"{provider} daily budget exhausted ({count}/{self._limit(provider)} UTC requests)."
            )

    def reserve_request(self, provider: str) -> None:
        self.ensure_budget(provider)
        interval = self._interval(provider)
        previous = self.last_request_at.get(provider)
        if previous is not None:
            remaining = interval - (self.monotonic() - previous)
            if remaining > 0:
                self.sleep(remaining)
        counter = self._counter(provider)
        self.usage[counter] += 1
        atomic_json(self.quota_path, self.usage)  # Persist before the network call, including 429s.
        self.last_request_at[provider] = self.monotonic()

    @staticmethod
    def retry_after(response: Any) -> float | None:
        value = getattr(response, "headers", {}).get("Retry-After")
        try:
            return max(0.0, float(value)) if value is not None else None
        except (TypeError, ValueError):
            return None

    def request(self, provider: str, method: str, url: str, **kwargs: Any) -> Any:
        interval = self._interval(provider)
        for attempt in range(MAX_429_RETRIES):
            self.reserve_request(provider)
            response = getattr(self.session, method)(url, timeout=(10, 30), **kwargs)
            if response.status_code != 429:
                return response
            retry_after = self.retry_after(response)
            response.close()
            if attempt + 1 >= MAX_429_RETRIES:
                raise EnrichmentError(
                    f"{provider} continued returning HTTP 429 after bounded exponential backoff."
                )
            exponential = min(BACKOFF_BASE_SECONDS * (2 ** attempt), BACKOFF_MAX_SECONDS)
            self.sleep(max(interval, exponential, retry_after or 0.0))
            # Backoff already exceeds the inter-request interval.
            self.last_request_at[provider] = self.monotonic() - interval
        raise EnrichmentError(f"{provider} retry loop ended unexpectedly.")

    def virustotal_malicious_count(self, digest: str, api_key: str) -> int | str:
        response = self.request(
            "virustotal",
            "get",
            VT_URL.format(sha256=digest),
            headers={"x-apikey": api_key, "Accept": "application/json"},
        )
        if response.status_code == 404:
            response.close()
            return "Not Found"
        if response.status_code != 200:
            response.raise_for_status()
            raise EnrichmentError(f"VirusTotal returned unexpected HTTP {response.status_code}.")
        try:
            malicious = response.json()["data"]["attributes"]["last_analysis_stats"]["malicious"]
        except (ValueError, KeyError, TypeError) as error:
            raise EnrichmentError("VirusTotal response omitted last_analysis_stats.malicious.") from error
        if type(malicious) is not int or malicious < 0:
            raise EnrichmentError("VirusTotal malicious count was not a non-negative integer.")
        return malicious

    def hybrid_analysis_result(self, digest: str, api_key: str) -> tuple[int | float | str, str]:
        response = self.request(
            "hybrid_analysis",
            "post",
            HA_URL,
            headers={
                "api-key": api_key,
                "user-agent": USER_AGENT,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data={"hash": digest},
        )
        if response.status_code == 404:
            response.close()
            return "Not Found", "Not Found"
        if response.status_code != 200:
            response.raise_for_status()
            raise EnrichmentError(f"Hybrid Analysis returned unexpected HTTP {response.status_code}.")
        try:
            payload = response.json()
        except ValueError as error:
            raise EnrichmentError("Hybrid Analysis returned invalid JSON.") from error
        if isinstance(payload, list):
            candidates = payload
        elif isinstance(payload, dict):
            nested = payload.get("result") or payload.get("results") or payload.get("data")
            candidates = nested if isinstance(nested, list) else [payload]
        else:
            raise EnrichmentError("Hybrid Analysis response must be an object or array.")
        record = next(
            (item for item in candidates
             if isinstance(item, dict) and str(item.get("sha256", "")).lower() == digest),
            next((item for item in candidates if isinstance(item, dict)), None),
        )
        if record is None:
            return "Not Found", "Not Found"
        score = record.get("threat_score")
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(float(score)):
            score = "Not Found"
        verdict = record.get("verdict")
        if not isinstance(verdict, str) or not verdict.strip():
            verdict = "Not Found"
        return score, verdict.strip()


def read_hashes(path: Path) -> list[str]:
    if not path.is_file():
        raise EnrichmentError(f"ThreatFox SHA-256 IOC list is missing: {path}")
    output: list[str] = []
    seen: set[str] = set()
    for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), start=1):
        digest = raw.strip().lower()
        if not digest:
            continue
        if not SHA256_RE.fullmatch(digest):
            raise EnrichmentError(f"Invalid SHA-256 on input line {line_number}.")
        if digest not in seen:
            seen.add(digest)
            output.append(digest)
    return output


def load_existing(path: Path) -> set[str]:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", newline="", encoding="utf-8") as stream:
            csv.DictWriter(stream, fieldnames=CSV_FIELDS).writeheader()
        return set()
    with path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != CSV_FIELDS:
            raise EnrichmentError("Existing enrichment CSV header does not match the required schema.")
        existing: set[str] = set()
        for row in reader:
            digest = str(row.get("sha256") or "").strip().lower()
            if not SHA256_RE.fullmatch(digest):
                raise EnrichmentError("Existing enrichment CSV contains an invalid SHA-256.")
            existing.add(digest)
        return existing


def append_record(path: Path, record: dict[str, Any]) -> None:
    with path.open("a", newline="", encoding="utf-8") as stream:
        csv.DictWriter(stream, fieldnames=CSV_FIELDS).writerow(record)
        stream.flush()
        os.fsync(stream.fileno())


def enrich_hashes(hashes_path: Path, csv_path: Path, quota_path: Path, *, session=None,
                  sleep=None, monotonic=None) -> dict[str, int]:
    hashes = read_hashes(hashes_path)
    existing = load_existing(csv_path)
    pending = [digest for digest in hashes if digest not in existing]
    cached = len(hashes) - len(pending)
    if not pending:
        print("Threat enrichment: no uncached SHA-256 hashes; provider quotas unchanged.")
        return {"seen": len(hashes), "added": 0, "cached": cached}

    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    ha_key = os.environ.get("HYBRID_ANALYSIS_API_KEY", "").strip()
    vt_approved = os.environ.get("VIRUSTOTAL_COMMERCIAL_USE_APPROVED", "").strip().lower()
    # No commercial VirusTotal license is configured for this project. A missing
    # key OR missing approval disables VT safely and records the -1 sentinel.
    vt_enabled = bool(vt_key) and vt_approved == "true"
    if not vt_enabled:
        reason = "API key is absent" if not vt_key else "commercial-use approval is absent"
        print(f"VirusTotal disabled ({reason}); recording vt_malicious_count=-1.")
    if not ha_key:
        raise EnrichmentError("HYBRID_ANALYSIS_API_KEY is not configured; no Hybrid Analysis calls were made.")

    client = ReputationClient(session or requests.Session(), quota_path, sleep=sleep, monotonic=monotonic)
    added = 0
    for digest in pending:
        try:
            client.ensure_budget("hybrid_analysis")
        except DailyQuotaReached as error:
            print(f"Threat enrichment paused safely: {error}")
            break

        vt_count = -1
        if vt_enabled:
            try:
                client.ensure_budget("virustotal")
                vt_count = client.virustotal_malicious_count(digest, vt_key)
            except DailyQuotaReached as error:
                print(f"VirusTotal disabled for the remainder of this UTC day: {error}")
                vt_enabled = False
                vt_count = -1

        ha_score, ha_verdict = client.hybrid_analysis_result(digest, ha_key)
        append_record(csv_path, {
            "sha256": digest,
            "vt_malicious_count": vt_count,
            "ha_threat_score": ha_score,
            "ha_verdict": ha_verdict,
        })
        existing.add(digest)
        added += 1
    print(f"Threat enrichment: added={added}; skipped cached={cached}; total input={len(hashes)}.")
    return {"seen": len(hashes), "added": added, "cached": cached}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hashes", type=Path, default=Path("data/new_hashes.txt"))
    parser.add_argument("--cache", type=Path, default=Path("data/enriched_threats.csv"))
    parser.add_argument("--quota-state", type=Path, default=Path("data/enrichment_quota.json"))
    args = parser.parse_args()
    enrich_hashes(args.hashes, args.cache, args.quota_state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
