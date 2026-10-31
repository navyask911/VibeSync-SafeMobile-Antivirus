#!/usr/bin/env python3
"""Prepare exactly 100 real verified malware APK hashes from ONE pinned static list.

No bulk or search API requests to MalwareBazaar. The only MalwareBazaar query
used here is get_file for an individual SHA-256. No malware payloads are
committed, installed, executed, shared as GitHub artifacts, or redistributed.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from benchmark_apk_validation import InvalidAndroidAPK, unpack_malwarebazaar_apk

API = "https://mb-api.abuse.ch/api/v1/"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STATIC_LIST_URL = (
    "https://raw.githubusercontent.com/"
    "Trustworthy-Software/Reproduction-of-Android-Malware-detection-approaches/"
    "9d4df09bedff63a78db2d2f48a24eeb95f45c531/"
    "dataset/malscan/2018_malware.txt"
)
STATIC_LIST_LIMIT = 300
STATIC_LIST_BYTES_LIMIT = 512 * 1024
APK_ARCHIVE_LIMIT = 90 * 1024 * 1024

class DatasetUnavailable(Exception):
    pass


def get_static_hashes_once(url=STATIC_LIST_URL):
    """Fetch a single pinned GitHub raw file, never MalwareBazaar discovery."""
    if url != STATIC_LIST_URL:
        raise DatasetUnavailable("Unapproved static hash-list URL")
    req = urllib.request.Request(url, headers={"User-Agent": "SafeMobileIndustryBenchmark/1.2"})
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            if response.status != 200 or response.url != url:
                raise DatasetUnavailable("Static SHA-256 URL redirected or returned an error")
            data = response.read(STATIC_LIST_BYTES_LIMIT + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise DatasetUnavailable("Pinned static GitHub SHA-256 list unavailable") from exc
    if not data or len(data) > STATIC_LIST_BYTES_LIMIT:
        raise DatasetUnavailable("Static hash list is missing or exceeds fixed limit")
    return data


def parse_static_hash_list(raw, limit=STATIC_LIST_LIMIT):
    if not isinstance(raw,bytes) or not raw or len(raw)>STATIC_LIST_BYTES_LIMIT:
        raise DatasetUnavailable("Static hash-list bytes invalid")
    if limit!=300:
        raise DatasetUnavailable("Only the 300-candidate pilot is approved")
    try:
        lines=raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise DatasetUnavailable("Static hash list is not UTF-8") from exc
    hashes=[];seen=set()
    for line in lines:
        s=line.strip().lower()
        if not s or s.startswith("#"):
            continue
        # Static 2018-malware dataset has precisely one SHA-256 per line.
        # Reject malformed entries instead of parsing text containing extra hashes.
        if not SHA256.fullmatch(s):
            raise DatasetUnavailable("Malformed SHA-256 entry in pinned GitHub list")
        if s in seen:
            continue
        seen.add(s)
        hashes.append(s)
        if len(hashes)==limit:
            break
    if len(hashes)!=300:
        raise DatasetUnavailable(f"Static source had only {len(hashes)} unique SHA-256 entries; 300 required")
    return hashes


def post_api(fields, key, max_bytes=4*1024*1024):
    # Fail closed on any attempt to reintroduce API-based corpus discovery.
    if set(fields) != {"query", "sha256_hash"} or fields.get("query") != "get_file" or not SHA256.fullmatch(str(fields.get("sha256_hash",""))):
        raise DatasetUnavailable("Only individual get_file by pinned SHA-256 is allowed")
    if not key or len(key)<8:
        raise DatasetUnavailable("MALWAREBAZAAR_AUTH_KEY is missing; configure GitHub Actions secret.")
    req=urllib.request.Request(API,data=urllib.parse.urlencode(fields).encode("ascii"),method="POST",headers={
        "Auth-Key":key,"Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":"SafeMobileIndustryBenchmark/1.2"})
    try:
        with urllib.request.urlopen(req,timeout=90) as resp:
            if resp.status==429: raise DatasetUnavailable("MalwareBazaar HTTP 429 rate limit; stop this run.")
            if resp.status!=200: raise DatasetUnavailable(f"MalwareBazaar HTTP {resp.status}.")
            raw=resp.read(max_bytes+1)
    except urllib.error.HTTPError as e:
        if e.code==429: raise DatasetUnavailable("MalwareBazaar HTTP 429 rate limit; stop this run.") from e
        if e.code in (401,403): raise DatasetUnavailable(f"MalwareBazaar auth/quota rejected (HTTP {e.code}).") from e
        raise DatasetUnavailable(f"MalwareBazaar HTTP {e.code}; sample unavailable.") from e
    except (urllib.error.URLError,TimeoutError) as e:
        raise DatasetUnavailable("MalwareBazaar API unreachable or timed out.") from e
    if len(raw)>max_bytes: raise DatasetUnavailable("MalwareBazaar API payload exceeds download limit.")
    return raw


def is_global_api_error(error):
    value=str(error).lower()
    return any(s in value for s in ("rate limit","429","quota","auth/","missing","401","403","api unreachable","timed out"))


def manifest_from_static_hashes(hashes, validator, source_digest):
    if len(hashes)!=300 or len(set(hashes))!=300 or any(not SHA256.fullmatch(x) for x in hashes):
        raise DatasetUnavailable("Expected exactly 300 unique SHA-256s from pinned static list")
    selected=[];rejected=0
    for index,sha in enumerate(hashes,1):
        try:
            # Each hash is validated exactly once against MalwareBazaar bytes.
            # Missing or non-APK records are rejected before the manifest is pinned.
            validator(sha)
        except InvalidAndroidAPK as error:
            rejected+=1
            print(f"WARNING: invalid Android APK {sha[:12]}: {error}",file=sys.stderr,flush=True)
            continue
        except DatasetUnavailable as error:
            if is_global_api_error(error):
                raise
            rejected+=1
            print(f"WARNING: unavailable APK {sha[:12]}: {error}",file=sys.stderr,flush=True)
            continue
        selected.append({"sha256":sha,"provider":"malwarebazaar","label":"malicious",
                         "source_filename":sha+".apk"})
        print(f"Validated APK {len(selected)}/100 after candidate {index}/300",flush=True)
        if len(selected)==100:
            break
    if len(selected)!=100:
        raise DatasetUnavailable(f"Only {len(selected)} valid APKs among 300 precompiled SHA-256 candidates "
                                 f"(rejected/unavailable {rejected}); no incomplete report will be published.")
    return {"schema_version":1,"name":"Static-dataset SHA-256, MalwareBazaar byte-verified APKs",
        "revision":"pinned 2018 Android malware hash list; 300 candidates; downloaded APK contents validated",
        "license":"Research hash-list provenance (see pinned GitHub source); malware binaries not redistributed",
        "source":STATIC_LIST_URL,
        "generated_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verified_apk_count":100,"rejected_candidate_count":rejected,
        "source_sha256":source_digest,"candidate_limit":300,"samples":selected}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    try:
        list_bytes=get_static_hashes_once()
        hashes=parse_static_hash_list(list_bytes)
        print("Downloaded exactly one immutable GitHub static SHA-256 list; "
              "300 unique candidates pinned. No MalwareBazaar search/bulk query.",flush=True)
        key=os.getenv("MALWAREBAZAAR_AUTH_KEY","")
        if not key or len(key)<8:
            raise DatasetUnavailable("MALWAREBAZAAR_AUTH_KEY is missing.")
        def verify(sha):
            # Only one get_file request for each SHA during preparation.
            try:
                raw=post_api({"query":"get_file","sha256_hash":sha},key,
                             max_bytes=APK_ARCHIVE_LIMIT)
                unpack_malwarebazaar_apk(raw,sha,sha+".apk")
            finally:
                # Pace individual requests (including unavailable/corrupt ones)
                # to reduce burst pressure. Rate-limit responses still abort.
                time.sleep(0.75)
        manifest=manifest_from_static_hashes(hashes,verify,hashlib.sha256(list_bytes).hexdigest())
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n",encoding="utf8")
        print(f"Prepared 100 byte-verified Android APK hashes; "
              f"skipped {manifest['rejected_candidate_count']} invalid/unavailable candidates.")
    except (DatasetUnavailable,ValueError,TypeError) as error:
        sys.exit("BENCHMARK UNAVAILABLE: "+str(error)+" No metrics published.")


if __name__=="__main__":
    main()
