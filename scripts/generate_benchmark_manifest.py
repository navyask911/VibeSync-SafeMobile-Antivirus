#!/usr/bin/env python3
"""Read-only benchmark preflight for 500 pinned SHA-named GitHub-hosted samples.

Read only data/benchmark-malware-hashes.txt from the Git tree. Download bytes
exclusively into $RUNNER_TEMP at runtime, never into source checkout. No
MalwareBazaar dependency, no executable malware, and no binary artifacts.
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

from benchmark_apk_validation import InvalidAndroidAPK, validate_apk_bytes, unpack_malwarebazaar_apk

SOURCE_COMMIT = "cf802c63baf8d435e8d4e663a24187056be3918a"
SOURCE_REPO = "MalwareSamples/Android-Malware-Samples"
LIST_PATH = Path(__file__).resolve().parent.parent / "data/benchmark-malware-hashes.txt"
HEX = re.compile(r"^[a-f0-9]{64}$")
MAX_DOWNLOAD = 90 * 1024 * 1024


class DatasetUnavailable(Exception):
    pass


class InvalidSample(Exception):
    pass


def sample_url(sha256):
    if not HEX.fullmatch(str(sha256)):
        raise DatasetUnavailable("Invalid pinned SHA-256 hash")
    return f"https://raw.githubusercontent.com/{SOURCE_REPO}/{SOURCE_COMMIT}/{sha256}"


def read_hashes(path=LIST_PATH):
    lines=Path(path).read_text(encoding="ascii").splitlines()
    if len(lines)!=500 or any(not HEX.fullmatch(s) for s in lines) or len(set(lines))!=500:
        raise DatasetUnavailable("Expected exactly 500 distinct SHA-256 filename entries")
    return lines


def download_and_validate(sha256):
    """Pinned HTTPS download -> APK validation or infected ZIP extraction in memory."""
    req=urllib.request.Request(sample_url(sha256),headers={
        "User-Agent":"SafeMobileReadOnlyBenchmark/1.4"})
    try:
        with urllib.request.urlopen(req,timeout=100) as response:
            if response.status!=200:
                raise InvalidSample(f"GitHub sample HTTP {response.status}")
            mime=response.headers.get("Content-Type","").lower().split(";",1)[0].strip()
            if mime in ("text/html","application/json"):
                raise InvalidSample(f"Not binary; Content-Type={mime}")
            data=response.read(MAX_DOWNLOAD+1)
    except urllib.error.HTTPError as error:
        if error.code in (403,429):
            raise DatasetUnavailable(f"Upstream GitHub HTTP {error.code}; halt instead of hammering source") from error
        raise InvalidSample(f"GitHub HTTP {error.code}") from error
    except (urllib.error.URLError,TimeoutError,OSError) as error:
        raise InvalidSample("Upstream download unavailable") from error
    if not data or len(data)>MAX_DOWNLOAD:
        raise InvalidSample("Missing or oversized sample")
    if data.lstrip().startswith((b"{",b"[",b"<html",b"<!DOCTYPE")):
        raise InvalidSample("HTML/JSON error body is not a malware APK")
    if not data.startswith(b"PK\x03\x04"):
        raise InvalidSample("Not ZIP magic PK-03-04")
    try:
        return validate_apk_bytes(data,sha256)
    except InvalidAndroidAPK:
        try:
            return unpack_malwarebazaar_apk(data,sha256,sha256+".apk")
        except InvalidAndroidAPK as error:
            raise InvalidSample(f"Neither installable APK nor infected ZIP: {error}") from error


def select_verified(hashes, scratch, fetcher=download_and_validate):
    if len(hashes)!=500 or len(set(hashes))!=500:
        raise DatasetUnavailable("Exactly 500 unique candidate hashes required")
    Path(scratch).mkdir(parents=True,exist_ok=True)
    chosen=[]
    for i,sha in enumerate(hashes,1):
        try:
            apk=fetcher(sha)
            validate_apk_bytes(apk,sha)
        except (InvalidSample,InvalidAndroidAPK) as error:
            print(f"WARNING: skip candidate {sha[:12]}: {error}",file=sys.stderr,flush=True)
            continue
        # Only ephemeral runner scratch; never Git checkout or GitHub artifacts.
        (Path(scratch)/(sha+".apk")).write_bytes(apk)
        chosen.append({"sha256":sha,"provider":"github-malware-samples",
                       "label":"malicious","source_filename":sha+".apk",
                       "url":sample_url(sha)})
        print(f"Verified real Android APK {len(chosen)}/100, candidate {i}/500",flush=True)
        if len(chosen)==100:break
    if len(chosen)!=100:
        raise DatasetUnavailable(f"Only {len(chosen)} valid Android APKs out of 500 source files; no metrics published")
    return {"schema_version":1,"name":"500 GitHub-hosted Android malware research candidates",
            "revision":"Pinned source commit "+SOURCE_COMMIT,
            "license":"Research-only, source-derived labels; binary redistribution prohibited",
            "source":"https://github.com/"+SOURCE_REPO,
            "source_commit":SOURCE_COMMIT,
            "generated_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verified_apk_count":100,"samples":chosen}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:
        tmp=Path(os.environ["RUNNER_TEMP"]).resolve()
        scratch=tmp/"industry"/"verified-malware"
        result=select_verified(read_hashes(),scratch)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        print("Pinned 100 real byte-verified APK SHA-256s; metadata only will be uploaded")
    except (DatasetUnavailable,OSError,ValueError,TypeError) as error:
        sys.exit("BENCHMARK UNAVAILABLE: "+str(error)+" No metrics published.")

if __name__=="__main__":main()
