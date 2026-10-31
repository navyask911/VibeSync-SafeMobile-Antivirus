#!/usr/bin/env python3
"""Prepare exactly 100 verified malware APK hashes from ONE recent API query.

One recent_detections(hours=168) discovery call, then get_file by SHA-256. No malware payloads are
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
APK_ARCHIVE_LIMIT = 90 * 1024 * 1024

class DatasetUnavailable(Exception):
    pass



class SampleUnavailable(DatasetUnavailable):
    """Individual sample not available; caller may skip to the next candidate."""


def parse_api_json(raw, http_status, query):
    try:
        data=json.loads(raw.decode("utf-8"))
    except (UnicodeError,ValueError) as exc:
        raise DatasetUnavailable(f"MalwareBazaar {query} HTTP {http_status}: invalid JSON") from exc
    if not isinstance(data,dict):
        raise DatasetUnavailable("MalwareBazaar expected JSON object")
    state=str(data.get("query_status","unknown")).lower()
    if query=="recent_detections" and state=="ok" and http_status==200:
        return data
    # Exact error fields only; never expose credentials or entire detection data.
    fields={"query_status":data.get("query_status","unknown")}
    for name in ("message","error","reason"):
        if name in data:fields[name]=str(data[name])[:200]
    detail=json.dumps(fields,sort_keys=True)
    message=f"MalwareBazaar {query} HTTP {http_status} JSON: {detail}"
    if http_status in (401,403,429) or state in (
            "rate_limit","too_many_requests","no_api_key","user_blacklisted",
            "quota_exceeded","daily_limit_reached","unauthorized","forbidden"):
        raise DatasetUnavailable(message)
    if query=="get_file" and state in ("file_not_found","no_results","illegal_sha256_hash"):
        raise SampleUnavailable(message)
    raise DatasetUnavailable(message)


def post_api(fields, key, max_bytes=4*1024*1024):
    """Authenticated discovery JSON or authenticated per-SHA encrypted ZIP bytes."""
    query=fields.get("query")
    if query=="recent_detections":
        if fields!={"query":"recent_detections","hours":"168"}:
            raise DatasetUnavailable("Only recent_detections hours=168 discovery is allowed")
    elif query=="get_file":
        if set(fields)!={"query","sha256_hash"} or not SHA256.fullmatch(
                str(fields.get("sha256_hash",""))):
            raise DatasetUnavailable("get_file requires valid pinned SHA-256")
    else:
        raise DatasetUnavailable("Historical/bulk discovery query prohibited")
    if not key or len(key)<8:
        raise DatasetUnavailable("MALWAREBAZAAR_AUTH_KEY is missing")
    request=urllib.request.Request(API,method="POST",
        data=urllib.parse.urlencode(fields).encode("ascii"),
        headers={"Auth-Key":key,"Content-Type":"application/x-www-form-urlencoded",
                 "Accept":"application/json" if query=="recent_detections" else "*/*",
                 "User-Agent":"SafeMobileIndustryBenchmark/1.3"})
    try:
        with urllib.request.urlopen(request,timeout=90) as response:
            status=response.status
            content_type=response.headers.get("Content-Type","").lower().split(";",1)[0].strip()
            raw=response.read(max_bytes+1)
    except urllib.error.HTTPError as exc:
        status=exc.code
        content_type=exc.headers.get("Content-Type","").lower() if exc.headers else ""
        raw=exc.read(4096)
        if "json" in content_type or raw.lstrip().startswith(b"{"):
            return parse_api_json(raw,status,query)
        if status in (401,403,429):
            raise DatasetUnavailable(f"MalwareBazaar {query} HTTP {status}: auth/quota/rate limit")
        if query=="get_file" and status==404:
            raise SampleUnavailable("MalwareBazaar get_file HTTP 404 file_not_found")
        raise DatasetUnavailable(f"MalwareBazaar {query} HTTP {status}")
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        raise DatasetUnavailable(f"MalwareBazaar {query}: network failure") from exc
    if len(raw)>max_bytes:
        if query=="get_file":
            raise SampleUnavailable("MalwareBazaar get_file: response exceeds size cap")
        raise DatasetUnavailable("MalwareBazaar recent response exceeds size cap")
    if status!=200:
        raise DatasetUnavailable(f"MalwareBazaar {query} HTTP {status}")
    if content_type=="application/json" or content_type.endswith("+json") or raw.lstrip().startswith((b"{",b"[")):
        return parse_api_json(raw,status,query)
    if query=="recent_detections":
        raise DatasetUnavailable(f"recent_detections returned non-JSON Content-Type {content_type}")
    if content_type and content_type not in ("application/zip","application/octet-stream",
                                            "application/x-zip-compressed","application/x-zip"):
        raise SampleUnavailable(f"MalwareBazaar get_file non-ZIP Content-Type {content_type}")
    if not raw.startswith(b"PK\x03\x04"):
        raise SampleUnavailable(f"MalwareBazaar get_file HTTP 200 Content-Type {content_type or 'unknown'}: not ZIP magic")
    return raw


def is_global_api_error(error):
    value=str(error).lower()
    return any(s in value for s in ("rate limit","429","quota","auth/","missing","401","403","api unreachable","timed out"))


def parse_recent_candidates(payload):
    if not isinstance(payload,dict) or payload.get("query_status")!="ok":
        raise DatasetUnavailable("Recent API returned invalid query_status")
    rows=payload.get("data")
    if not isinstance(rows,list):
        raise DatasetUnavailable("Recent API has no data list")
    candidates=[];seen=set()
    for row in rows:
        if not isinstance(row,dict):continue
        sha=str(row.get("sha256_hash","")).lower()
        if not SHA256.fullmatch(sha) or sha in seen:continue
        kind=str(row.get("file_type","")).lower()
        name=str(row.get("file_name","")).lower()
        mime=str(row.get("file_type_mime","")).lower()
        if kind in ("exe","elf","dll","dex","jar","pdf","js","doc"):continue
        if not (kind=="apk" or name.endswith(".apk") or
                mime=="application/vnd.android.package-archive"):continue
        seen.add(sha)
        candidates.append({"sha256":sha,"provider":"malwarebazaar",
                           "label":"malicious","source_filename":sha+".apk"})
        if len(candidates)==300:break
    print(f"One recent_detections query: {len(rows)} detections, "
          f"{len(candidates)} Android APK candidates (cap 300)",flush=True)
    return candidates


def manifest_from_recent(payload,validator):
    candidates=parse_recent_candidates(payload)
    valid=[];skipped=0
    for i,row in enumerate(candidates,1):
        try:
            validator(row)
        except (SampleUnavailable,InvalidAndroidAPK) as error:
            skipped+=1
            print(f"WARNING: skip {row['sha256'][:12]}: {error}",file=sys.stderr,flush=True)
            continue
        # Auth, quota, HTTP 429/403 must propagate; never keep hammering provider.
        valid.append(row)
        print(f"Validated recent APK {len(valid)}/100 at candidate {i}",flush=True)
        if len(valid)==100:break
    if len(valid)!=100:
        raise DatasetUnavailable(f"Only {len(valid)}/100 valid malicious APKs among "
                                 f"{len(candidates)} recent candidates, {skipped} skipped; no metrics published")
    return {"schema_version":1,"name":"MalwareBazaar recent verified Android APKs",
        "revision":"recent_detections hours=168; one discovery query; get_file byte validation",
        "license":"MalwareBazaar Community API research terms; no binary redistribution",
        "source":"https://bazaar.abuse.ch/api/",
        "generated_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verified_apk_count":100,"rejected_candidate_count":skipped,
        "candidate_limit":300,"discovered_apk_candidates":len(candidates),
        "samples":valid}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,type=Path)
    args=parser.parse_args()
    try:
        key=os.environ.get("MALWAREBAZAAR_AUTH_KEY","")
        response=post_api({"query":"recent_detections","hours":"168"},key,
                          max_bytes=32*1024*1024)
        print("Exactly one recent_detections(hours=168) discovery request completed",flush=True)
        def verify(row):
            try:
                zip_bytes=post_api({"query":"get_file","sha256_hash":row["sha256"]},
                                   key,max_bytes=APK_ARCHIVE_LIMIT)
                unpack_malwarebazaar_apk(zip_bytes,row["sha256"],row["source_filename"])
            finally:
                time.sleep(0.75)
        manifest=manifest_from_recent(response,verify)
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
        print(f"Pinned 100 validated recent APKs; skipped {manifest['rejected_candidate_count']}")
    except (DatasetUnavailable,ValueError,TypeError,OSError) as error:
        sys.exit("BENCHMARK UNAVAILABLE: "+str(error)+" No metrics published.")

if __name__=="__main__":main()
