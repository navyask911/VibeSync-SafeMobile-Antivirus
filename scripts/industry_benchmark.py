#!/usr/bin/env python3
"""Download pinned APKs in ephemeral CI, validate real scanner results, never invent metrics."""
import argparse, datetime, hashlib, json, os, re, shutil, statistics, sys, time, urllib.parse, urllib.request, zipfile
from pathlib import Path
INDEX="https://f-droid.org/repo/index-v1.json"
HEX=re.compile(r"^[a-f0-9]{64}$")
MAX_APK=75*1024*1024

def bad(s): raise ValueError(s)
def digest(data): return hashlib.sha256(data).hexdigest()
def save(path, obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n",encoding="utf8")
def fetch(url,limit):
    p=urllib.parse.urlsplit(url)
    if p.scheme!="https" or not p.hostname or p.username or p.password or p.hostname in ("localhost","127.0.0.1"):
        bad("Expected public HTTPS URL without credentials")
    req=urllib.request.Request(url,headers={"User-Agent":"SafeMobileIndustryBenchmark/1.0"})
    with urllib.request.urlopen(req,timeout=120) as res:
        if urllib.parse.urlsplit(res.url).scheme!="https": bad("Unsafe redirect")
        if int(res.headers.get("Content-Length","0"))>limit: bad("File too large")
        raw=res.read(limit+1)
    if len(raw)>limit: bad("Download exceeded size limit")
    return raw

def prepare(a):
    url=os.environ.get("INDUSTRY_MALWARE_MANIFEST_URL","")
    pin=os.environ.get("INDUSTRY_MALWARE_MANIFEST_SHA256","").lower()
    if not url or not HEX.fullmatch(pin):
        bad("Set repo variables INDUSTRY_MALWARE_MANIFEST_URL and INDUSTRY_MALWARE_MANIFEST_SHA256 to an owner-approved, licensed 1,000-APK manifest. No public mirror is presumed safe.")
    raw=fetch(url,4*1024*1024)
    if digest(raw)!=pin: bad("Malware manifest SHA-256 does not match owner's approval")
    m=json.loads(raw)
    if m.get("schema_version")!=1 or len(m.get("samples",[]))!=1000: bad("Malware manifest requires schema_version=1 and exactly 1000 samples")
    for key in ("name","revision","license","source"):
        if not isinstance(m.get(key),str) or not m[key].strip(): bad("Missing malware dataset attribution: "+key)
    mal=[]
    for i,s in enumerate(m["samples"]):
        sha=str(s.get("sha256","")).lower()
        if not HEX.fullmatch(sha): bad("Invalid malware sample digest")
        fetch_url=s.get("url","")
        p=urllib.parse.urlsplit(fetch_url)
        if p.scheme!="https" or not p.hostname: bad("Invalid malware sample URL")
        mal.append(dict(sample_id="m%04d"%i,label="malicious",sha256=sha,url=fetch_url,relative_path="m%04d.apk"%i))
    index_raw=fetch(INDEX,125*1024*1024)
    index=json.loads(index_raw)["packages"]
    benign=[]
    for pkg,versions in sorted(index.items()):
        versions=[v for v in versions if isinstance(v,dict) and HEX.fullmatch(str(v.get("hash","")).lower())
           and isinstance(v.get("size"),int) and 0<v["size"]<=MAX_APK
           and re.fullmatch(r"[A-Za-z0-9_.+-]+\.apk",str(v.get("apkName","")))]
        if versions:
            v=max(versions,key=lambda x:int(x.get("versionCode",0)))
            i=len(benign)
            benign.append(dict(sample_id="b%04d"%i,label="benign",sha256=v["hash"].lower(),url="https://f-droid.org/repo/"+v["apkName"],relative_path="b%04d.apk"%i))
        if len(benign)==1000: break
    if len(benign)!=1000 or len(set(s["sha256"] for s in benign+mal))!=2000:
        bad("Not exactly 1000 benign and 1000 distinct malicious SHA-256s")
    save(a.plan,dict(schema_version=1,samples=benign+mal,provenance=dict(
        fdroid_index_sha256=digest(index_raw),malware_manifest_sha256=pin,
        malware_name=m["name"],malware_revision=m["revision"],malware_license=m["license"],
        malware_source=m["source"],commit=os.environ.get("GITHUB_SHA","unknown"))))
    print("Approved manifest checked; exactly 2000 pinned APK references prepared")

def stage(a):
    selected=json.loads(a.plan.read_text())["samples"][a.offset:a.offset+25]
    if len(selected)!=25: bad("Incomplete 25-file batch")
    shutil.rmtree(a.root,ignore_errors=True);a.root.mkdir(parents=True)
    for s in selected:
        raw=fetch(s["url"],MAX_APK)
        if digest(raw)!=s["sha256"]: bad("Downloaded APK digest mismatch: "+s["sample_id"])
        target=a.root/s["relative_path"];target.write_bytes(raw)
        try:
            with zipfile.ZipFile(target) as z:
                if "AndroidManifest.xml" not in z.namelist(): bad("Not an APK: "+s["sample_id"])
        except zipfile.BadZipFile: bad("Invalid APK zip: "+s["sample_id"])
    save(a.root/"batch.json",dict(samples=[{k:s[k] for k in ("sample_id","label","sha256")} for s in selected]))
    print("Staged pinned batch %d..%d" % (a.offset,a.offset+24),flush=True)

def summarize(a):
    plan_bytes=a.plan.read_bytes();plan=json.loads(plan_bytes)
    refs={s["sample_id"]:s for s in plan["samples"]}
    results={}
    for path in sorted(a.results.glob("batch-*.json")):
        for s in json.loads(path.read_text())["samples"]:
            sid=s["sample_id"]
            if sid not in refs or sid in results: bad("Unexpected or duplicate result")
            if s["label"]!=refs[sid]["label"] or s["sha256"]!=refs[sid]["sha256"]:
                bad("Device-reported digest or label differs from pinned corpus")
            if s["verdict"] not in ("THREAT","SUSPICIOUS","NO_MATCH","NOT_SCANNED"):
                bad("Unknown verdict")
            if not isinstance(s.get("duration_ms"),(int,float)) or s["duration_ms"]<0:bad("Invalid elapsed time")
            results[sid]=s
    if len(results)!=2000 or set(results)!=set(refs):bad("Benchmark incomplete: %d/2000 actual scans"%len(results))
    b=[x for x in results.values() if x["label"]=="benign"]
    m=[x for x in results.values() if x["label"]=="malicious"]
    unread=sum(x["verdict"]=="NOT_SCANNED" for x in results.values())
    good=unread==0
    pct=lambda xs,flags:round(100*sum(x["verdict"] in flags for x in xs)/len(xs),3)
    output=dict(status="MEASURED" if good else "INCOMPLETE",
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        total_apps=2000,benign_apps=1000,malicious_apps=1000,not_scanned=unread,
        tpr_percent=pct(m,("THREAT",)) if good else None,
        fpr_percent=pct(b,("THREAT",)) if good else None,
        triage_tpr_percent=pct(m,("THREAT","SUSPICIOUS")) if good else None,
        triage_fpr_percent=pct(b,("THREAT","SUSPICIOUS")) if good else None,
        mean_latency_ms=round(statistics.fmean(x["duration_ms"] for x in results.values()),2) if good else None,
        ml_samples_scored=sum(x.get("ml_scored",False) for x in results.values()),
        yara_states=sorted(set(x.get("yara_state","UNKNOWN") for x in results.values())),
        plan_sha256=digest(plan_bytes),provenance=plan["provenance"])
    save(a.output_json,output)
    report="# SafeMobile Industry Benchmark Report\n\n"
    report+="Read-only Android emulator APK scans (samples NEVER installed/executed). "
    report+="THREAT counts as a confirmed detection; SUSPICIOUS counts only for triage.\n\n"
    report+="## Benchmark result\n\n~~~json\n"+json.dumps(output,indent=2,sort_keys=True)+"\n~~~\n\n"
    report+="Models/definitions not active in the scanned build cannot contribute to measured efficacy. "
    report+="Results apply only to this corpus, emulator and commit.\n"
    a.output_markdown.parent.mkdir(parents=True,exist_ok=True)
    a.output_markdown.write_text(report)
    if not good: bad("%d actual scans returned NOT_SCANNED; report marked INCOMPLETE"%unread)
    print("Completed 2000 verified read-only APK scans; aggregate metrics generated")

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest="mode",required=True)
    q=sub.add_parser("prepare");q.add_argument("--plan",type=Path,required=True)
    q=sub.add_parser("stage");q.add_argument("--plan",type=Path,required=True);q.add_argument("--root",type=Path,required=True);q.add_argument("--offset",type=int,required=True)
    q=sub.add_parser("summarize");q.add_argument("--plan",type=Path,required=True);q.add_argument("--results",type=Path,required=True)
    q.add_argument("--output-json",type=Path,required=True);q.add_argument("--output-markdown",type=Path,required=True)
    a=p.parse_args()
    try: globals()[a.mode](a)
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as e: sys.exit("Benchmark cannot publish metrics: "+str(e))
if __name__=="__main__":main()
