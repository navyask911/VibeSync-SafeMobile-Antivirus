#!/usr/bin/env python3
"""Fetch ThreatFox SHA-256 IOCs and build a bounded SafeMobile .hsb database.

ThreatFox get_iocs supplies IOC metadata, not APK sample binaries. This script
only extracts records whose ioc_type is sha256_hash. It never downloads samples
or truncates an oversized database.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import sys
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterator, Any

import requests

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
MAX_COMPRESSED_BYTES = 128 * 1024 * 1024
MAX_DATABASE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 200_000
MAX_LINE_BYTES = 4096
SHA256_RE = re.compile(r"[a-fA-F0-9]{64}\Z")
LICENSE_RE = re.compile(r"[A-Za-z0-9.+-]{1,80}\Z")
SOURCE = "threatfox.abuse.ch"
THREAT_NAME = "ThreatFox.SHA256"


class InputRejected(ValueError):
    """ThreatFox response or hash export is malformed or exceeds app limits."""


def fetch_recent_iocs(auth_key: str, days: int = 1, *, session=None) -> dict[str, Any]:
    """Fetch ThreatFox recent IOCs using the documented Auth-Key header."""
    if not auth_key or not auth_key.strip():
        raise InputRejected("THREATFOX_AUTH_KEY is not configured.")
    if type(days) is not int or not 1 <= days <= 7:
        raise InputRejected("ThreatFox days must be an integer from 1 to 7.")
    client = session or requests.Session()
    with client.post(
        API_URL,
        headers={
            "Auth-Key": auth_key.strip(),
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SafeMobile-Threat-Intelligence/1.0",
        },
        json={"query": "get_iocs", "days": days},
        timeout=(15, 60),
        allow_redirects=False,
    ) as response:
        response.raise_for_status()
        if len(response.content) > MAX_COMPRESSED_BYTES:
            raise InputRejected("ThreatFox response exceeds the 128 MiB safety limit.")
        try:
            payload = response.json()
        except ValueError as error:
            raise InputRejected("ThreatFox returned invalid JSON.") from error
    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        status = payload.get("query_status", "missing") if isinstance(payload, dict) else "invalid"
        raise InputRejected(f"ThreatFox query_status was {status!r}.")
    if not isinstance(payload.get("data"), list):
        raise InputRejected("ThreatFox response is missing its data array.")
    return payload


def sha256_iocs(payload: dict[str, Any]) -> list[str]:
    """Return unique valid ioc values from SHA-256 IOC records only."""
    if not isinstance(payload, dict) or payload.get("query_status") != "ok":
        raise InputRejected("Invalid ThreatFox IOC payload.")
    records = payload.get("data")
    if not isinstance(records, list):
        raise InputRejected("ThreatFox data must be an array.")
    output: list[str] = []
    seen: set[str] = set()
    for row_number, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue
        if str(record.get("ioc_type", "")).strip().lower() != "sha256_hash":
            continue
        value = record.get("ioc")
        if not isinstance(value, str):
            raise InputRejected(f"ThreatFox SHA-256 IOC {row_number} has no string ioc value.")
        digest = value.strip().lower()
        if not SHA256_RE.fullmatch(digest):
            raise InputRejected(f"ThreatFox SHA-256 IOC {row_number} is malformed.")
        if digest not in seen:
            seen.add(digest)
            output.append(digest)
    if not output:
        raise InputRejected("ThreatFox returned no valid sha256_hash IOCs; refusing to publish an empty feed.")
    return output


@contextmanager
def input_lines(path: Path) -> Iterator[BinaryIO]:
    if not path.is_file() or not (0 < path.stat().st_size <= MAX_COMPRESSED_BYTES):
        raise InputRejected("Empty export or compressed download exceeds 128 MiB")
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(path) as archive:
            texts = []
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                name = PurePosixPath(entry.filename)
                if name.is_absolute() or ".." in name.parts or "\\" in entry.filename:
                    raise InputRejected("Unexpected ZIP traversal name")
                if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise InputRejected("ZIP symlinks forbidden")
                if name.suffix.lower() == ".txt":
                    texts.append(entry)
            if len(texts) != 1:
                raise InputRejected("ZIP must contain exactly one SHA-256 .txt export")
            entry = texts[0]
            if entry.file_size > MAX_COMPRESSED_BYTES or (entry.flag_bits & 1):
                raise InputRejected("Export decompression limit or encrypted ZIP")
            with archive.open(entry, "r") as contents:
                yield contents
    elif magic[:2] == b"\x1f\x8b":
        with gzip.open(path, "rb") as contents:
            yield contents
    else:
        with path.open("rb") as contents:
            yield contents


def convert(source: Path, destination: Path, version: int, license_id: str,
            date: str | None = None, *, max_records: int = MAX_RECORDS,
            max_bytes: int = MAX_DATABASE_BYTES,
            hashes_output: Path | None = None) -> dict[str, int]:
    if version <= 0 or version >= (1 << 63):
        raise InputRejected("Version must be a positive signed 64-bit integer")
    if not LICENSE_RE.fullmatch(license_id):
        raise InputRejected("Commercial license/permission reference required")
    if date is None:
        date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", date):
        raise InputRejected("DATE must be UTC ISO-8601 seconds")
    lines = [
        f"# SAFEHASH version={version} source={SOURCE} license={license_id}\n".encode("ascii"),
        b"# VERSION: 1\n",
        f"# DATE: {date}\n".encode("ascii"),
    ]
    total_bytes = sum(map(len, lines))
    if total_bytes > max_bytes:
        raise InputRejected("Header exceeds database size limit")
    seen: set[bytes] = set()
    ordered_hashes: list[str] = []
    with input_lines(source) as stream:
        while True:
            row = stream.readline(MAX_LINE_BYTES + 1)
            if not row:
                break
            if len(row) > MAX_LINE_BYTES:
                raise InputRejected("Oversized line; possible corrupt or HTML response")
            line = row.strip()
            if not line or line.startswith(b"#"):
                continue
            try:
                digest = line.decode("ascii").lower()
            except UnicodeDecodeError as exc:
                raise InputRejected("Export must contain only ASCII SHA-256 text") from exc
            if not SHA256_RE.fullmatch(digest):
                raise InputRejected("Non-hash entry or HTML/API error in export")
            key = line.lower()
            if key in seen:
                raise InputRejected("Duplicate SHA-256 in export: review required")
            seen.add(key)
            ordered_hashes.append(digest)
            record = f"{digest}:{THREAT_NAME}\n".encode("ascii")
            total_bytes += len(record)
            if len(seen) > max_records or total_bytes > max_bytes:
                raise InputRejected(
                    f"Full export exceeds Android parser limits: {len(seen)} rows, {total_bytes} bytes; "
                    f"max {max_records} rows, {max_bytes} bytes. "
                    "Do not truncate or publish a partial export: upgrade the app parser first."
                )
            lines.append(record)
    if not seen:
        raise InputRejected("Export contains no SHA-256 entries")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".partial")
    try:
        with temporary.open("wb") as output:
            output.writelines(lines)
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    if hashes_output is not None:
        hashes_output = Path(hashes_output)
        hashes_output.parent.mkdir(parents=True, exist_ok=True)
        hashes_temporary = hashes_output.with_suffix(hashes_output.suffix + ".partial")
        try:
            hashes_temporary.write_text("".join(value + "\n" for value in ordered_hashes), encoding="ascii")
            hashes_temporary.replace(hashes_output)
        finally:
            hashes_temporary.unlink(missing_ok=True)
    return {"records": len(seen), "bytes": total_bytes, "version": version}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--license-id", required=True,
                        help="Actual commercial redistribution permission/license reference; not a CC0 assertion")
    parser.add_argument("--hashes-output", type=Path, required=True)
    parser.add_argument("--iocs-output", type=Path, default=Path("threatfox_iocs.json"))
    parser.add_argument("--days", type=int, default=1)
    parser.add_argument("--input-json", type=Path,
                        help="Offline fixture input; normally the script fetches directly from ThreatFox")
    args = parser.parse_args()
    try:
        if args.input_json:
            payload = json.loads(args.input_json.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("query_status") != "ok":
                raise InputRejected("Offline ThreatFox fixture has an invalid query_status.")
            if not isinstance(payload.get("data"), list):
                raise InputRejected("Offline ThreatFox fixture is missing its data array.")
        else:
            payload = fetch_recent_iocs(os.environ.get("THREATFOX_AUTH_KEY", ""), args.days)
        hashes = sha256_iocs(payload)
        args.iocs_output.parent.mkdir(parents=True, exist_ok=True)
        args.iocs_output.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
        args.hashes_output.parent.mkdir(parents=True, exist_ok=True)
        args.hashes_output.write_text("".join(value + "\n" for value in hashes), encoding="ascii")
        report = convert(args.hashes_output, args.output, args.version, args.license_id)
    except (InputRejected, OSError, EOFError, zipfile.BadZipFile, requests.RequestException, json.JSONDecodeError) as exc:
        print(f"SAFE FAILURE: {exc}", file=sys.stderr)
        return 2
    print(f"Validated ThreatFox response: {len(payload['data'])} IOCs, {len(hashes)} unique SHA-256 hashes; "
          f"database {report['records']} records, {report['bytes']} bytes, version {report['version']}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
