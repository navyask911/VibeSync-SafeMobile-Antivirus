#!/usr/bin/env python3
"""Download, validate, extract, inspect, and index the Mendeley dataset for research use only."""
from __future__ import annotations
import argparse, collections, csv, hashlib, json, os, re, shutil, sqlite3, stat, tempfile, time
import urllib.error, urllib.request, zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

DATASET_ID = "xv84w8cc72"
DATASET_VERSION = 1
DATASET_TITLE = "A 200K Malware Hash Dataset with Experimental Splits for Machine Learning Classification"
DATASET_URL = "https://data.mendeley.com/public-api/zip/xv84w8cc72/download/1"
LANDING_PAGE = "https://data.mendeley.com/datasets/xv84w8cc72/1"
DATASET_DOI = "10.17632/xv84w8cc72.1"
LICENSE_NAME = "Creative Commons Attribution 4.0 International (CC BY 4.0)"
LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
CREATORS = ["Antonio Lara Gutiérrez", "Nicolas Alvarez", "Jose A Onieva"]
CHUNK = 1024 * 1024
MIN_FREE = 128 * 1024 * 1024
MAX_DOWNLOAD = 2 * 1024 * 1024 * 1024
MAX_ENTRIES = 50000
MAX_UNCOMPRESSED = 8 * 1024 * 1024 * 1024
MAX_RATIO = 1000
BATCH = 1000
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
HASH_FIELDS = ("sha256", "sha256hash", "hashsha256", "filesha256", "sha256digest", "sha256sum", "samplehash", "filehash", "hash")
LABEL_FIELDS = ("binarylabel", "labelbinary", "binaryclass", "classlabel", "label", "classification", "class", "target", "ismalware", "malware", "groundtruth")


class DatasetError(RuntimeError):
    pass


def now_utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def norm_name(value):
    return re.sub(r"[^a-z0-9]", "", value.strip().lower())


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def check_free_space(path, required):
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    if free < required:
        raise DatasetError(f"Insufficient disk space: need about {required} bytes; {free} bytes free at {path}.")


def safe_parts(name):
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise DatasetError(f"Unsafe ZIP member path: {name!r}")
    pieces = name.split("/")
    if name.endswith("/"):
        pieces = pieces[:-1]
    if not pieces or any(p in {"", ".", ".."} for p in pieces):
        raise DatasetError(f"ZIP path traversal or malformed member: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise DatasetError(f"ZIP path traversal is not permitted: {name!r}")
    return tuple(pieces)


def validate_zip(path):
    if not path.is_file() or path.stat().st_size < 22:
        raise DatasetError(f"Archive missing or too small: {path}")
    if path.stat().st_size > MAX_DOWNLOAD:
        raise DatasetError("Archive exceeds the configured 2 GiB size limit.")
    if not zipfile.is_zipfile(path):
        with path.open("rb") as stream:
            prefix = stream.read(512).lstrip().lower()
        if prefix.startswith((b"<html", b"<!doctype html", b"<?xml")):
            raise DatasetError("Server returned HTML/XML rather than a ZIP archive.")
        raise DatasetError("Downloaded file is not a valid ZIP archive.")
    manifest_paths, seen = [], set()
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ENTRIES:
            raise DatasetError(f"Archive entry count is invalid: {len(infos)}.")
        total = 0
        for info in infos:
            parts = safe_parts(info.filename)
            folded = "/".join(parts).casefold()
            if folded in seen:
                raise DatasetError(f"Duplicate ZIP path: {info.filename!r}")
            seen.add(folded)
            if info.flag_bits & 1:
                raise DatasetError(f"Encrypted ZIP entries are not supported: {info.filename!r}")
            mode = info.external_attr >> 16
            kind = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode) or kind not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise DatasetError(f"Symlinks and special filesystem entries are not allowed: {info.filename!r}")
            if info.file_size < 0 or info.compress_size < 0:
                raise DatasetError(f"Invalid ZIP member sizes: {info.filename!r}")
            total += info.file_size
            if total > MAX_UNCOMPRESSED:
                raise DatasetError("Expanded archive exceeds the 8 GiB safety limit.")
            if info.file_size and info.compress_size == 0:
                raise DatasetError(f"Invalid compressed size: {info.filename!r}")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise DatasetError(f"Suspicious compression ratio: {info.filename!r}")
            if PurePosixPath(info.filename).name.lower() == "manifest.csv" and not info.is_dir():
                manifest_paths.append("/".join(parts))
        if len(manifest_paths) != 1:
            raise DatasetError(f"Expected exactly one manifest.csv; found {len(manifest_paths)}: {manifest_paths}")
        bad = archive.testzip()
        if bad:
            raise DatasetError(f"ZIP CRC check failed for {bad!r}.")
    return {"archive_bytes": path.stat().st_size, "entry_count": len(infos),
            "uncompressed_bytes": total, "manifest_member": manifest_paths[0]}


def download_zip(url, archive_path, timeout, retries, max_bytes):
    if not url.lower().startswith("https://"):
        raise DatasetError("Dataset URL must use HTTPS.")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists():
        try:
            return validate_zip(archive_path), True, url
        except (DatasetError, OSError, zipfile.BadZipFile):
            # Preserve the invalid archive for diagnosis; never silently overwrite it.
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = archive_path.with_name(archive_path.name + ".invalid-" + stamp)
            index = 1
            while backup.exists():
                backup = archive_path.with_name(archive_path.name + f".invalid-{stamp}-{index}")
                index += 1
            archive_path.rename(backup)
    last_error = None
    for attempt in range(1, retries + 1):
        temp_path = None
        try:
            check_free_space(archive_path.parent, MIN_FREE)
            request = urllib.request.Request(url, headers={
                "User-Agent": "SafeMobile-Dataset-Inspector/1.0",
                "Accept": "application/zip, application/octet-stream, */*",
            })
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = getattr(response, "status", 200)
                if status < 200 or status >= 300:
                    raise DatasetError(f"Dataset server returned HTTP {status}.")
                final_url = response.geturl()
                if not final_url.lower().startswith("https://"):
                    raise DatasetError("Dataset download redirected to a non-HTTPS URL.")
                length = response.headers.get("Content-Length")
                expected = int(length) if length else None
                if expected is not None:
                    if expected < 22 or expected > max_bytes:
                        raise DatasetError("Content-Length is outside allowed download bounds.")
                    check_free_space(archive_path.parent, expected + MIN_FREE)
                fd, name = tempfile.mkstemp(prefix=archive_path.name + ".part-", dir=archive_path.parent)
                temp_path = Path(name)
                digest = hashlib.sha256()
                downloaded = 0
                with os.fdopen(fd, "wb") as output:
                    while True:
                        block = response.read(CHUNK)
                        if not block:
                            break
                        downloaded += len(block)
                        if downloaded > max_bytes:
                            raise DatasetError("Download exceeded configured size limit.")
                        output.write(block)
                        digest.update(block)
                    output.flush()
                    os.fsync(output.fileno())
            if expected is not None and downloaded != expected:
                raise DatasetError(f"Incomplete download: expected {expected} bytes; received {downloaded}.")
            validation = validate_zip(temp_path)
            os.replace(temp_path, archive_path)
            temp_path = None
            validation["downloaded_bytes"] = downloaded
            validation["download_stream_sha256"] = digest.hexdigest()
            return validation, False, final_url
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, DatasetError, zipfile.BadZipFile) as error:
            last_error = error
            if attempt < retries:
                time.sleep(min(2 ** (attempt - 1), 8))
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
    raise DatasetError(f"Download failed after {retries} attempts: {last_error}") from last_error


def extract_safely(archive_path, destination, archive_hash):
    marker_name = ".mendeley-verification.json"
    marker_path = destination / marker_name
    if destination.is_dir() and marker_path.is_file():
        try:
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            manifest = destination / marker["manifest_relative_path"]
            if (marker.get("archive_sha256") == archive_hash and manifest.is_file()
                    and file_sha256(manifest) == marker.get("manifest_sha256")):
                stats = validate_zip(archive_path)
                return {"reused_extraction": True, "manifest_relative_path": marker["manifest_relative_path"],
                        "manifest_sha256": marker["manifest_sha256"], "entry_count": stats["entry_count"],
                        "uncompressed_bytes": stats["uncompressed_bytes"]}
        except (OSError, ValueError, KeyError, TypeError, DatasetError):
            pass

    destination.parent.mkdir(parents=True, exist_ok=True)
    check_free_space(destination.parent, MIN_FREE)
    staging = Path(tempfile.mkdtemp(prefix=destination.name + ".staging-", dir=destination.parent))
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            infos = archive.infolist()
            total = sum(info.file_size for info in infos)
            check_free_space(destination.parent, total + MIN_FREE)
            for info in infos:
                parts = safe_parts(info.filename)
                target = staging.joinpath(*parts)
                try:
                    target.resolve().relative_to(staging.resolve())
                except ValueError as error:
                    raise DatasetError(f"ZIP path escaped output root: {info.filename!r}") from error
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while True:
                        block = source.read(CHUNK)
                        if not block:
                            break
                        written += len(block)
                        if written > info.file_size or written > MAX_UNCOMPRESSED:
                            raise DatasetError(f"Expanded entry exceeded limits: {info.filename!r}")
                        output.write(block)
                if written != info.file_size:
                    raise DatasetError(f"Expanded size mismatch: {info.filename!r}")
        manifests = [p for p in staging.rglob("*") if p.is_file() and p.name.lower() == "manifest.csv"]
        if len(manifests) != 1:
            raise DatasetError(f"Expected one extracted manifest.csv; found {len(manifests)}.")
        manifest = manifests[0]
        marker = {"archive_sha256": archive_hash,
                  "manifest_relative_path": manifest.relative_to(staging).as_posix(),
                  "manifest_sha256": file_sha256(manifest), "verified_at_utc": now_utc()}
        (staging / marker_name).write_text(json.dumps(marker, indent=2) + "\n", encoding="utf-8")
        if destination.exists():
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            backup = destination.with_name(destination.name + ".previous-" + stamp)
            suffix = 1
            while backup.exists():
                backup = destination.with_name(destination.name + f".previous-{stamp}-{suffix}")
                suffix += 1
            destination.rename(backup)
        os.replace(staging, destination)
        staging = None
        return {"reused_extraction": False, "manifest_relative_path": marker["manifest_relative_path"],
                "manifest_sha256": marker["manifest_sha256"], "entry_count": len(infos),
                "uncompressed_bytes": total}
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def pick_column(headers, explicit, candidates, purpose):
    by_normalized = {}
    for header in headers:
        key = norm_name(header)
        if key in by_normalized:
            raise DatasetError(f"Ambiguous CSV headers normalize to {key!r}: {by_normalized[key]!r}, {header!r}.")
        by_normalized[key] = header
    if explicit:
        key = norm_name(explicit)
        if key not in by_normalized:
            raise DatasetError(f"Requested {purpose} column {explicit!r} is absent. Actual headers: {headers}")
        return by_normalized[key]
    for candidate in candidates:
        if candidate in by_normalized:
            return by_normalized[candidate]
    raise DatasetError(f"Cannot identify {purpose} column from actual headers {headers}; pass an explicit column option.")


def import_manifest(manifest, database, hash_column=None, label_column=None):
    if not manifest.is_file():
        raise DatasetError(f"manifest.csv not found: {manifest}")
    database.parent.mkdir(parents=True, exist_ok=True)
    staging_db = database.with_name(database.name + ".staging")
    staging_db.unlink(missing_ok=True)
    conn = None
    examined = valid = invalid = duplicates = 0
    labels, category_counts = collections.Counter(), collections.Counter()
    try:
        with manifest.open("r", encoding="utf-8-sig", newline="") as stream:
            csv.field_size_limit(4 * 1024 * 1024)
            reader = csv.DictReader(stream)
            if not reader.fieldnames:
                raise DatasetError("manifest.csv has no CSV header.")
            headers = list(reader.fieldnames)
            if any(not h.strip() for h in headers):
                raise DatasetError("manifest.csv has empty column names.")
            hash_name = pick_column(headers, hash_column, HASH_FIELDS, "hash")
            label_name = pick_column(headers, label_column, LABEL_FIELDS, "label")
            normalized = {header: norm_name(header) for header in headers}
            excluded = {hash_name, label_name}
            category_columns = [h for h in headers if h not in excluded and any(
                token in normalized[h] for token in ("family", "category", "threat", "subtype")
            )]
            split_columns = [h for h in headers if h not in excluded and any(
                token in normalized[h] for token in ("split", "train", "test", "experiment", "mask", "binary", "multiclass", "trimodal")
            )]
            conn = sqlite3.connect(staging_db)
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA temp_store=FILE")
            conn.executescript("""
                CREATE TABLE research_hashes (
                    row_number INTEGER PRIMARY KEY,
                    sha256 TEXT,
                    label_column TEXT NOT NULL,
                    label_value TEXT NOT NULL,
                    category_values_json TEXT NOT NULL,
                    split_values_json TEXT NOT NULL,
                    raw_record_json TEXT NOT NULL
                );
                CREATE INDEX research_hashes_sha256_idx ON research_hashes(sha256);
                CREATE TABLE research_seen_hashes (sha256 TEXT PRIMARY KEY, first_row_number INTEGER NOT NULL);
                CREATE TABLE import_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            batch = []
            for row_number, row in enumerate(reader, start=2):
                examined += 1
                raw = {str(key): value for key, value in row.items() if key is not None}
                value = (row.get(hash_name) or "").strip()
                normalized_hash = value.lower() if SHA256_RE.fullmatch(value) else None
                if normalized_hash:
                    valid += 1
                    inserted = conn.execute(
                        "INSERT OR IGNORE INTO research_seen_hashes(sha256, first_row_number) VALUES (?, ?)",
                        (normalized_hash, row_number),
                    ).rowcount
                    if not inserted:
                        duplicates += 1
                else:
                    invalid += 1
                label = (row.get(label_name) or "").strip()
                labels[label if label else "<empty>"] += 1
                cat = {key: (row.get(key) or "").strip() for key in category_columns}
                for value in cat.values():
                    if value:
                        category_counts[value] += 1
                splits = {key: (row.get(key) or "").strip() for key in split_columns}
                batch.append((
                    row_number, normalized_hash, label_name, label,
                    json.dumps(cat, ensure_ascii=False, separators=(",", ":")),
                    json.dumps(splits, ensure_ascii=False, separators=(",", ":")),
                    json.dumps(raw, ensure_ascii=False, separators=(",", ":")),
                ))
                if len(batch) >= BATCH:
                    conn.executemany("INSERT INTO research_hashes VALUES (?, ?, ?, ?, ?, ?, ?)", batch)
                    conn.commit()
                    batch.clear()
            if batch:
                conn.executemany("INSERT INTO research_hashes VALUES (?, ?, ?, ?, ?, ?, ?)", batch)
                conn.commit()
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise DatasetError("Generated research SQLite index failed PRAGMA integrity_check.")
            unique = conn.execute("SELECT COUNT(*) FROM research_seen_hashes").fetchone()[0]

            # Exercise indexed lookups against real imported records, not just schema creation.
            sample_hashes = [
                item[0] for item in conn.execute(
                    "SELECT sha256 FROM research_seen_hashes ORDER BY first_row_number LIMIT 5"
                )
            ]
            sample_lookup_checks = 0
            for sample_hash in sample_hashes:
                matched = conn.execute(
                    "SELECT row_number FROM research_hashes WHERE sha256 = ? ORDER BY row_number LIMIT 1",
                    (sample_hash,),
                ).fetchone()
                expected_row = conn.execute(
                    "SELECT first_row_number FROM research_seen_hashes WHERE sha256 = ?",
                    (sample_hash,),
                ).fetchone()
                if matched is None or expected_row is None or matched[0] != expected_row[0]:
                    raise DatasetError("Sample SHA-256 lookup verification failed.")
                plan = conn.execute(
                    "EXPLAIN QUERY PLAN SELECT row_number FROM research_hashes WHERE sha256 = ? LIMIT 1",
                    (sample_hash,),
                ).fetchall()
                if not any("research_hashes_sha256_idx" in str(plan_row) for plan_row in plan):
                    raise DatasetError("Sample lookup is not using the expected SHA-256 index.")
                sample_lookup_checks += 1

            if valid > 0 and sample_lookup_checks == 0:
                raise DatasetError("No sample SHA-256 lookups could be verified.")
            metadata = {
                "dataset_id": DATASET_ID, "version": str(DATASET_VERSION), "doi": DATASET_DOI,
                "research_only": "true", "hash_column": hash_name, "label_column": label_name,
                "rows_examined": str(examined), "valid_sha256_rows": str(valid),
                "invalid_hash_rows": str(invalid), "duplicate_hash_rows_after_first": str(duplicates),
                "unique_sha256_hashes": str(unique), "imported_at_utc": now_utc(),
            }
            conn.executemany("INSERT INTO import_metadata VALUES (?, ?)", list(metadata.items()))
            conn.commit()
            conn.close()
            conn = None
        os.replace(staging_db, database)
    except Exception:
        if conn is not None:
            conn.close()
        staging_db.unlink(missing_ok=True)
        staging_db.with_name(staging_db.name + "-journal").unlink(missing_ok=True)
        raise
    return {
        "database_file": database.name, "rows_examined": examined, "valid_sha256_rows": valid,
        "invalid_hash_rows": invalid, "duplicate_hash_rows_after_first": duplicates,
        "unique_sha256_hashes": unique, "hash_column": hash_name, "label_column": label_name,
        "sample_lookup_checks": sample_lookup_checks,
        "sample_lookup_validation": "passed",
        "sample_lookup_index": "research_hashes_sha256_idx",
        "headers": headers, "label_value_counts": dict(labels.most_common(100)),
        "label_value_count_truncated": len(labels) > 100,
        "category_value_counts_top_100": dict(category_counts.most_common(100)),
        "category_value_count_truncated": len(category_counts) > 100,
        "research_labels_not_verified_live_indicators": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DATASET_URL)
    parser.add_argument("--archive", type=Path, default=Path(".cache/datasets/mendeley_xv84w8cc72_v1.zip"))
    parser.add_argument("--output", type=Path, default=Path(".cache/datasets/mendeley_xv84w8cc72_v1"))
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--max-download-mib", type=int, default=2048)
    parser.add_argument("--hash-column", default=None)
    parser.add_argument("--label-column", default=None)
    args = parser.parse_args()
    if not args.url.lower().startswith("https://") or min(args.timeout, args.retries, args.max_download_mib) < 1:
        parser.error("Use an HTTPS URL and positive timeout/retry/size values.")
    try:
        archive_stats, reused, final_url = download_zip(
            args.url, args.archive.resolve(), args.timeout, args.retries,
            args.max_download_mib * 1024 * 1024,
        )
        archive_hash = file_sha256(args.archive.resolve())
        output = args.output.resolve()
        extraction = extract_safely(args.archive.resolve(), output, archive_hash)
        manifest = output / extraction["manifest_relative_path"]
        database = output / "research-index.sqlite3"
        imported = import_manifest(manifest, database, args.hash_column, args.label_column)
        report = {
            "dataset": {
                "id": DATASET_ID, "version": DATASET_VERSION, "title": DATASET_TITLE,
                "creators": CREATORS, "publisher": "Mendeley Data", "publication_date": "2026-09-14",
                "doi": DATASET_DOI, "landing_page": LANDING_PAGE,
                "related_dataset_link": "https://doi.org/10.5281/zenodo.19342248",
                "license": LICENSE_NAME, "license_url": LICENSE_URL,
            },
            "download": {
                "requested_url": args.url, "final_url": final_url, "archive_file": args.archive.name,
                "archive_bytes": archive_stats["archive_bytes"], "archive_sha256": archive_hash,
                "archive_reused": reused, "zip_integrity": "passed",
            },
            "extraction": extraction,
            "import": imported,
            "verification": {
                "source_archive_modified": False, "source_manifest_modified": False,
                "operational_room_database_modified": False, "dataset_bundled_in_apk": False,
                "research_sqlite_integrity": "passed",
            },
            "interpretation": (
                "Research index only. The source includes experimental malware and goodware labels. "
                "They are not authenticated operational threat intelligence and are not automatically used by the Android scanner."
            ),
            "run_at_utc": now_utc(),
        }
        report_path = output / "report.json"
        report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0
    except (DatasetError, OSError, urllib.error.URLError, zipfile.BadZipFile, csv.Error, sqlite3.Error) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
