#!/usr/bin/env python3
"""Produce an ephemeral, SHA256-pinned list of 100 MalwareBazaar Android APK candidates."""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

API = "https://mb-api.abuse.ch/api/v1/"
SHA256 = re.compile(r"^[0-9a-f]{64}$")

class DatasetUnavailable(Exception):
    pass

def post_api(fields, key, max_bytes=4*1024*1024):
    if not key or len(key)<8:
        raise DatasetUnavailable("MALWAREBAZAAR_AUTH_KEY is missing; configure GitHub Actions secret.")
    req=urllib.request.Request(API,data=urllib.parse.urlencode(fields).encode("ascii"),method="POST",headers={
        "Auth-Key":key,
        "Content-Type":"application/x-www-form-urlencoded",
        "User-Agent":"SafeMobileIndustryBenchmark/1.1"})
    try:
        with urllib.request.urlopen(req,timeout=90) as resp:
            if resp.status==429: raise DatasetUnavailable("MalwareBazaar HTTP 429 rate limit; retry later.")
            if resp.status!=200: raise DatasetUnavailable(f"MalwareBazaar HTTP {resp.status}; cannot benchmark.")
            raw=resp.read(max_bytes+1)
    except urllib.error.HTTPError as e:
        if e.code==429: raise DatasetUnavailable("MalwareBazaar HTTP 429 rate limit; retry later.") from e
        if e.code in (401,403): raise DatasetUnavailable(f"MalwareBazaar auth/quota rejected (HTTP {e.code}).") from e
        raise DatasetUnavailable(f"MalwareBazaar HTTP {e.code}; cannot benchmark.") from e
    except (urllib.error.URLError,TimeoutError) as e:
        raise DatasetUnavailable("MalwareBazaar API unreachable or timed out.") from e
    if len(raw)>max_bytes: raise DatasetUnavailable("MalwareBazaar API payload exceeds download limit.")
    return raw

def manifest_from_response(payload,count=100):
    status=payload.get("query_status")
    if status!="ok": raise DatasetUnavailable(f"MalwareBazaar query_status={status}; no numbers published.")
    data=payload.get("data")
    if not isinstance(data,list): raise DatasetUnavailable("MalwareBazaar returned no APK candidate rows.")
    seen=set(); candidates=[]
    for row in data:
        if not isinstance(row,dict): continue
        sha=str(row.get("sha256_hash","")).lower()
        is_apk=(str(row.get("file_type","")).lower()=="apk" or
                str(row.get("file_name","")).lower().endswith(".apk"))
        if not SHA256.fullmatch(sha) or sha in seen or not is_apk: continue
        seen.add(sha)
        candidates.append({"sha256":sha,"provider":"malwarebazaar","label":"malicious"})
    candidates.sort(key=lambda sample:hashlib.sha256(sample["sha256"].encode()).hexdigest())
    if len(candidates)<count:
        raise DatasetUnavailable(f"Only {len(candidates)} APK candidates; {count} required.")
    return {"schema_version":1,"name":"MalwareBazaar Android APK candidates",
        "revision":"get_file_type apk API snapshot",
        "license":"abuse.ch MalwareBazaar Community API fair-use terms; no redistribution",
        "source":"https://bazaar.abuse.ch/api/",
        "generated_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "samples":candidates[:count]}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    try:
        payload=json.loads(post_api({"query":"get_file_type","file_type":"apk","limit":"1000"},
                                    os.getenv("MALWAREBAZAAR_AUTH_KEY","")))
        manifest=manifest_from_response(payload)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
        print("Selected 100 pinned APK candidates; labels are not independently audited.")
    except (DatasetUnavailable,ValueError,TypeError) as error:
        sys.exit("BENCHMARK UNAVAILABLE: "+str(error)+" No metrics published.")

if __name__=="__main__":main()
