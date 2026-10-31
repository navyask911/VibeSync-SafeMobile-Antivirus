#!/usr/bin/env python3
"""Download pinned APKs in ephemeral CI, validate real scanner results, never invent metrics."""
import argparse, datetime, hashlib, io, json, os, re, shutil, statistics, sys, time, urllib.parse, urllib.request, zipfile
import generate_benchmark_manifest as malwarebazaar
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
    if not a.malware_manifest.is_file():
        bad("No MalwareBazaar candidate manifest available; refusing a partial benchmark.")
    raw=a.malware_manifest.read_bytes()
    manifest=json.loads(raw)
    if manifest.get("schema_version")!=1 or len(manifest.get("samples",[]))!=100:
        bad("Expected exactly 100 distinct MalwareBazaar candidate records.")
    for field in ("name","revision","license","source"):
        if not isinstance(manifest.get(field),str) or not manifest[field].strip():
            bad("Missing candidate provenance field "+field)
    malicious=[]
    for i,row in enumerate(manifest["samples"]):
        sha=str(row.get("sha256","")).lower()
        if row.get("provider")!="malwarebazaar" or not HEX.fullmatch(sha):
            bad("Malware candidate must have valid provider and SHA-256")
        malicious.append({"sample_id":"m%04d"%i,"label":"malicious","provider":"malwarebazaar",
                          "sha256":sha,"relative_path":"m%04d.apk"%i})
    index_raw=fetch(INDEX,125*1024*1024)
    index=json.loads(index_raw).get("packages")
    if not isinstance(index,dict): bad("F-Droid index format unexpected")
    benign=[]
    for package,versions in sorted(index.items()):
        if not isinstance(versions,list): continue
        valid=[v for v in versions if isinstance(v,dict) and
               HEX.fullmatch(str(v.get("hash","")).lower()) and
               isinstance(v.get("size"),int) and 0<v["size"]<=MAX_APK and
               re.fullmatch(r"[A-Za-z0-9_.+-]+\.apk",str(v.get("apkName","")))]
        if valid:
            v=max(valid,key=lambda x:int(x.get("versionCode",0)))
            benign.append({"label":"benign","sha256":v["hash"].lower(),
                           "url":"https://f-droid.org/repo/"+v["apkName"]})
    benign.sort(key=lambda x:hashlib.sha256(x["url"].encode()).hexdigest())
    benign=benign[:100]
    for i,row in enumerate(benign):
        row["sample_id"]="b%04d"%i
        row["relative_path"]="b%04d.apk"%i
    if len(benign)!=100 or len(set(x["sha256"] for x in benign+malicious))!=200:
        bad("Exactly 100 distinct F-Droid APKs and 100 distinct malware candidate hashes required")
    save(a.plan,{"schema_version":1,"samples":benign+malicious,"provenance":{
        "fdroid_index_sha256":digest(index_raw),"malware_manifest_sha256":digest(raw),
        "malware_name":manifest["name"],"malware_revision":manifest["revision"],
        "malware_license":manifest["license"],"malware_source":manifest["source"],
        "label_limitations":"MalwareBazaar/F-Droid source labels are not independently validated ground truth",
        "commit":os.environ.get("GITHUB_SHA","unknown")}})
    print("Prepared exactly 100 F-Droid + 100 MalwareBazaar-pinned candidate APK hashes")

def download_malware(sha):
    if not HEX.fullmatch(sha): bad("Invalid malware candidate SHA-256")
    try:
        raw=malwarebazaar.post_api({"query":"get_file","sha256_hash":sha},
            os.environ.get("MALWAREBAZAAR_AUTH_KEY",""),max_bytes=90*1024*1024)
    except malwarebazaar.DatasetUnavailable as e:
        bad("Cannot acquire pinned APK: "+str(e))
    if not raw.startswith(b"PK"):
        bad("MalwareBazaar returned no encrypted ZIP (sample unavailable or download quota exceeded)")
    import pyzipper
    try:
        with pyzipper.AESZipFile(io.BytesIO(raw)) as z:
            files=[entry for entry in z.infolist() if not entry.is_dir()]
            if len(files)!=1 or not 1<=files[0].file_size<=MAX_APK:
                bad("Unsafe or unexpected MalwareBazaar ZIP content/size")
            with z.open(files[0],pwd=b"infected") as src:
                payload=src.read(MAX_APK+1)
    except (RuntimeError,ValueError,zipfile.BadZipFile,EOFError) as e:
        bad("Cannot safely unpack encrypted APK ZIP: "+type(e).__name__)
    if len(payload)>MAX_APK or digest(payload)!=sha:
        bad("MalwareBazaar sample digest mismatch after encrypted ZIP extraction")
    return payload

def stage(a):
    selected=json.loads(a.plan.read_text())["samples"][a.offset:a.offset+10]
    if len(selected)!=10: bad("Incomplete 10-file batch")
    shutil.rmtree(a.root,ignore_errors=True);a.root.mkdir(parents=True)
    for s in selected:
        raw=download_malware(s["sha256"]) if s.get("provider")=="malwarebazaar" else fetch(s["url"],MAX_APK)
        if digest(raw)!=s["sha256"]: bad("Downloaded APK digest mismatch: "+s["sample_id"])
        target=a.root/s["relative_path"];target.write_bytes(raw)
        try:
            with zipfile.ZipFile(target) as z:
                if "AndroidManifest.xml" not in z.namelist(): bad("Not an APK: "+s["sample_id"])
        except zipfile.BadZipFile: bad("Invalid APK zip: "+s["sample_id"])
    save(a.root/"batch.json",dict(samples=[{k:s[k] for k in ("sample_id","label","sha256")} for s in selected]))
    print("Staged pinned batch %d..%d" % (a.offset,a.offset+9),flush=True)

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
    if len(results)!=200 or set(results)!=set(refs):bad("Benchmark incomplete: %d/200 actual scans"%len(results))
    b=[x for x in results.values() if x["label"]=="benign"]
    m=[x for x in results.values() if x["label"]=="malicious"]
    unread=sum(x["verdict"]=="NOT_SCANNED" for x in results.values())
    good=unread==0
    pct=lambda xs,flags:round(100*sum(x["verdict"] in flags for x in xs)/len(xs),3)
    research=[x for x in results.values() if isinstance(x.get("research_ml_probability"),(int,float))
        and not isinstance(x.get("research_ml_probability"),bool)
        and 0<=x["research_ml_probability"]<=1]
    research_valid=len(research)==len(results)
    research_detected=lambda subset:round(100*sum(x["research_ml_probability"]>=0.5 for x in subset)/len(subset),3)
    output=dict(status="MEASURED" if good else "INCOMPLETE",
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        total_apps=200,benign_apps=100,malicious_apps=100,not_scanned=unread,
        tpr_percent=pct(m,("THREAT",)) if good else None,
        fpr_percent=pct(b,("THREAT",)) if good else None,
        triage_tpr_percent=pct(m,("THREAT","SUSPICIOUS")) if good else None,
        triage_fpr_percent=pct(b,("THREAT","SUSPICIOUS")) if good else None,
        mean_latency_ms=round(statistics.fmean(x["duration_ms"] for x in results.values()),2) if good else None,
        ml_samples_scored=sum(x.get("ml_scored",False) for x in results.values()),
        research_ml_samples_scored=len(research),
        research_ml_tpr_percent=research_detected([x for x in research if x["label"]=="malicious"]) if research_valid else None,
        research_ml_fpr_percent=research_detected([x for x in research if x["label"]=="benign"]) if research_valid else None,
        research_ml_threshold=0.5,
        yara_states=sorted(set(x.get("yara_state","UNKNOWN") for x in results.values())),
        plan_sha256=digest(plan_bytes),provenance=plan["provenance"])
    save(a.output_json,output)
    report="# SafeMobile Industry Benchmark Report\n\n"
    report+="Read-only Android emulator APK scans (samples NEVER installed/executed). "
    report+="THREAT counts as a confirmed detection; SUSPICIOUS counts only for triage.\n\n"
    report+="## Benchmark result\n\n~~~json\n"+json.dumps(output,indent=2,sort_keys=True)+"\n~~~\n\n"
    report+="Research ML scores are independent of production threat verdicts; ML-only rates are shown only if all 200 samples were scored. "
    report+="Models/definitions not active in the scanned build cannot contribute to measured efficacy. "
    report+="Results apply only to this corpus, emulator and commit.\n"
    a.output_markdown.parent.mkdir(parents=True,exist_ok=True)
    a.output_markdown.write_text(report)
    if not good: bad("%d actual scans returned NOT_SCANNED; report marked INCOMPLETE"%unread)
    print("Completed 200 verified read-only APK scans; aggregate metrics generated")

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest="mode",required=True)
    q=sub.add_parser("prepare");q.add_argument("--plan",type=Path,required=True);q.add_argument("--malware-manifest",type=Path,required=True)
    q=sub.add_parser("stage");q.add_argument("--plan",type=Path,required=True);q.add_argument("--root",type=Path,required=True);q.add_argument("--offset",type=int,required=True)
    q=sub.add_parser("summarize");q.add_argument("--plan",type=Path,required=True);q.add_argument("--results",type=Path,required=True)
    q.add_argument("--output-json",type=Path,required=True);q.add_argument("--output-markdown",type=Path,required=True)
    a=p.parse_args()
    try: globals()[a.mode](a)
    except (OSError,ValueError,KeyError,TypeError,zipfile.BadZipFile) as e: sys.exit("Benchmark cannot publish metrics: "+str(e))
if __name__=="__main__":main()
