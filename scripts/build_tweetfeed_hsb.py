#!/usr/bin/env python3
"""Fetch public TweetFeed SHA-256 IOCs and build a bounded SAFEHASH database.

TweetFeed's public JSON API requires no API key. Its IOC data is CC0 1.0.
TweetFeed warns that the indicators are community-sourced and not independently
verified, so the SAFEHASH entry label deliberately says CommunityIOC.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any

import requests

API_URL = "https://api.tweetfeed.live/v1/week/malware/sha256"
SOURCE = "tweetfeed.live"
LICENSE = "CC0-1.0"
THREAT_NAME = "TweetFeed.CommunityIOC"
MAX_FEED_BYTES = 8 * 1024 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 200_000
SHA256_RE = re.compile(r"[a-fA-F0-9]{64}\Z")


class InputRejected(ValueError):
    """The feed response or its SHA-256 indicators are not safe to publish."""


def fetch_feed(*, session=None) -> list[dict[str, Any]]:
    """Fetch the documented public weekly malware-tagged SHA-256 feed."""
    client = session or requests.Session()
    response = client.get(
        API_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "SafeMobile-Threat-Intelligence/1.0",
        },
        timeout=(15, 60),
        allow_redirects=False,
    )
    try:
        response.raise_for_status()
        truncated = str(getattr(response, "headers", {}).get("X-Result-Truncated", "")).lower()
        if truncated == "true":
            raise InputRejected("TweetFeed marked the response as truncated; refusing a partial database.")
        content = response.content
        if not isinstance(content, bytes) or len(content) == 0:
            raise InputRejected("TweetFeed returned an empty response.")
        if len(content) > MAX_FEED_BYTES:
            raise InputRejected("TweetFeed response exceeds the 8 MiB safety limit.")
        try:
            payload = response.json()
        except ValueError as error:
            raise InputRejected("TweetFeed returned invalid JSON.") from error
    finally:
        response.close()

    if not isinstance(payload, list):
        raise InputRejected("TweetFeed response must be a JSON array.")
    if not all(isinstance(record, dict) for record in payload):
        raise InputRejected("TweetFeed response contains a non-object record.")
    return payload


def sha256_values(records: list[dict[str, Any]]) -> list[str]:
    """Extract unique SHA-256 record values; ignore other IOC types."""
    if not isinstance(records, list):
        raise InputRejected("TweetFeed records must be a JSON array.")

    hashes: list[str] = []
    seen: set[str] = set()
    for index, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise InputRejected(f"TweetFeed record {index} is not an object.")
        if str(record.get("type", "")).strip().lower() != "sha256":
            continue
        value = record.get("value")
        if not isinstance(value, str):
            raise InputRejected(f"TweetFeed SHA-256 record {index} has no string value.")
        digest = value.strip().lower()
        if not SHA256_RE.fullmatch(digest):
            raise InputRejected(f"TweetFeed SHA-256 record {index} contains a malformed digest.")
        if digest not in seen:
            seen.add(digest)
            hashes.append(digest)

    if not hashes:
        raise InputRejected("TweetFeed returned no usable SHA-256 values; refusing to publish an empty feed.")
    if len(hashes) > MAX_RECORDS:
        raise InputRejected(f"TweetFeed returned {len(hashes)} hashes; Android supports at most {MAX_RECORDS}.")
    return hashes


def build_database(
    hashes: list[str],
    output: Path,
    version: int,
    *,
    date: str | None = None,
    max_records: int = MAX_RECORDS,
    max_bytes: int = MAX_DATABASE_BYTES,
) -> dict[str, int]:
    """Write all validated hashes; never truncate an oversized source feed."""
    if type(version) is not int or not 0 < version < (1 << 63):
        raise InputRejected("Version must be a positive signed 64-bit integer.")
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", date):
        raise InputRejected("DATE must be UTC ISO-8601 seconds.")

    unique: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(hashes, start=1):
        if not isinstance(raw, str):
            raise InputRejected(f"Hash {index} is not a string.")
        digest = raw.strip().lower()
        if not SHA256_RE.fullmatch(digest):
            raise InputRejected(f"Hash {index} is not a valid SHA-256 digest.")
        if digest not in seen:
            seen.add(digest)
            unique.append(digest)
    if not unique:
        raise InputRejected("No SHA-256 hashes available to build the database.")
    if len(unique) > max_records:
        raise InputRejected("Full feed exceeds Android's record limit; do not truncate or publish a partial database.")

    lines = [
        f"# SAFEHASH version={version} source={SOURCE} license={LICENSE}\n",
        "# VERSION: 1\n",
        f"# DATE: {date}\n",
    ]
    lines.extend(f"{digest}:{THREAT_NAME}\n" for digest in unique)
    content = "".join(lines).encode("ascii")
    if len(content) > max_bytes:
        raise InputRejected(
            f"Full feed is {len(content)} bytes; Android limit is {max_bytes}. "
            "Do not truncate or publish a partial database."
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".partial")
    try:
        temporary.write_bytes(content)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return {"records": len(unique), "bytes": len(content), "version": version}


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    try:
        temporary.write_text(content, encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--hashes-output", type=Path, required=True)
    parser.add_argument("--feed-json", type=Path, default=Path("tweetfeed_iocs.json"))
    parser.add_argument("--input-json", type=Path, help="Offline fixture; normal runs fetch the public API.")
    args = parser.parse_args()

    try:
        if args.input_json:
            records = json.loads(args.input_json.read_text(encoding="utf-8"))
        else:
            records = fetch_feed()
        hashes = sha256_values(records)
        report = build_database(hashes, args.output, args.version)
        write_text_atomic(args.hashes_output, "".join(f"{digest}\n" for digest in hashes))
        write_text_atomic(args.feed_json, json.dumps(records, separators=(",", ":"), allow_nan=False) + "\n")
    except (InputRejected, OSError, requests.RequestException, json.JSONDecodeError, TypeError, ValueError) as error:
        print(f"SAFE FAILURE: {error}", file=sys.stderr)
        return 2

    print(
        f"Validated TweetFeed response: {len(records)} records, {len(hashes)} unique SHA-256 IOCs; "
        f"database {report['records']} records, {report['bytes']} bytes, "
        f"version {report['version']}; license={LICENSE}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
