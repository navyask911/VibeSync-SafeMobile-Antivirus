#!/usr/bin/env python3
"""Opt-in ThreatFox IOC -> local APK -> frozen Drebin-215 feature vectors.

Defensive static inspection ONLY: never execute APK code, upload samples or store
sample ZIP/APK bytes in GitHub Actions artifacts. Failures are per-sample and do
not change the separately signed hash database. Run in the ephemeral CI runner.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import zipfile

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "app/src/main/assets/feature_schema.json"
SCHEMA_SHA256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
INVOKE = re.compile(r"(L[A-Za-z0-9_/$-]+;)->([A-Za-z0-9_$<>]+)\(")
MAX_APK_BYTES = 20 * 1024 * 1024
MAX_CODE_METHODS = 120_000
MAX_CODE_INSTRUCTIONS = 1_500_000
MAX_STRINGS = 200_000
CLASS_FEATURES = {
    "ServiceConnection", "ClassLoader", "DexClassLoader", "SecretKey", "KeySpec",
    "Binder", "IBinder", "URLClassLoader", "PathClassLoader", "PackageInstaller",
    "HttpUriRequest", "MessengerService", "IRemoteService", "ProcessBuilder",
    "android.os.Binder", "android.os.IBinder", "android.content.pm.Signature",
    "android.telephony.SmsManager", "android.telephony.gsm.SmsManager",
    "android.content.pm.PackageInfo", "Ljava.net.URLDecoder",
    "Ljavax.crypto.spec.SecretKeySpec", "Ljavax.crypto.Cipher",
}
CALLBACKS = {"onBind", "onServiceConnected"}
COMMANDS = {"mount", "remount", "chmod", "chown"}


class SampleRejected(ValueError):
    """Corrupt, non-Android or over-budget content; skip without a verdict."""


def schema_features(path: Path = SCHEMA_PATH) -> list[str]:
    raw = path.read_bytes()
    if len(raw) > 32 * 1024 or hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
        raise ValueError("Pinned feature schema mismatch; refusing cross-model dispatch")
    schema = json.loads(raw)
    if not isinstance(schema, dict) or list(schema) != [str(i) for i in range(215)]:
        raise ValueError("Drebin schema must have indexed keys 0..214 in order")
    features = list(schema.values())
    if any(not isinstance(x, str) or not x for x in features) or len(set(features)) != 215:
        raise ValueError("Drebin schema must contain 215 unique feature names")
    return features


def class_name(value: str) -> str:
    return value.lstrip("[").removeprefix("L").removesuffix(";").replace("/", ".")


def feature_vector(schema: list[str], *, permissions=(), actions=(), classes=(),
                   calls=(), callbacks=(), literals=()) -> list[int]:
    """Mirror DrebinFeatureContract.kt semantics; never search APK raw bytes."""
    if len(schema) != 215 or len(set(schema)) != 215:
        raise ValueError("Invalid 215-feature schema")
    rights = set()
    for item in permissions:
        for prefix in ("android.permission.", "com.android.browser.permission."):
            if item.startswith(prefix):
                rights.add(item[len(prefix):])
                break
    actions = set(actions)
    classes = {class_name(str(item)) for item in classes}
    simple = {item.rsplit(".", 1)[-1] for item in classes}
    resolved_calls = set()
    for owner, name in calls:
        cls = class_name(str(owner))
        name = "init" if name == "<init>" else str(name)
        resolved_calls.update((name, f"{cls}.{name}", f"{cls.rsplit('.', 1)[-1]}.{name}"))
    callbacks = set(callbacks)
    literals = tuple(str(value) for value in literals)

    def indicator(value: str) -> bool:
        if all(char.isupper() or char.isdigit() or char == "_" for char in value):
            return value in rights
        if "intent.action." in value:
            return value in actions or (
                value == "intent.action.RUN" and "android.intent.action.RUN" in actions
            )
        if value in CLASS_FEATURES:
            normalized = class_name(value)
            return normalized in classes or ("." not in normalized and normalized in simple)
        if value in COMMANDS:
            return any(re.search(r"(?<![A-Za-z0-9_])" + re.escape(value) +
                                 r"(?![A-Za-z0-9_])", literal) for literal in literals)
        if value.startswith("/system/"):
            return any(re.search(re.escape(value) + r"(?=/|$|\s)", literal)
                       for literal in literals)
        method = value[1:] if value.startswith(("Ljava.", "Ljavax.", "Landroid.")) else value
        return method in resolved_calls or (value in CALLBACKS and value in callbacks)

    return [int(indicator(name)) for name in schema]


def analyze_android_apk(path: Path, schema: list[str], analyzer=None) -> list[int]:
    """Parse binary manifest and every DEX with Androguard; never load code."""
    if analyzer is None:
        # Androguard uses noisy DEBUG logs by default, including raw manifest
        # strings. Keep malware sample internals and credentials out of CI logs.
        from loguru import logger
        import sys
        logger.remove()
        logger.add(sys.stderr, level="ERROR")
        from androguard.misc import AnalyzeAPK
        analyzer = AnalyzeAPK
    apk, dexes, _ = analyzer(str(path))
    if not apk.is_valid_APK() or not dexes:
        raise SampleRejected("Invalid Android manifest or missing DEX")
    permissions = set(apk.get_permissions())
    actions = set()
    for kind, components in (
        ("activity", apk.get_activities()),
        ("service", apk.get_services()),
        ("receiver", apk.get_receivers()),
    ):
        for component in components:
            filters = apk.get_intent_filters(kind, component) or {}
            actions.update(filters.get("action", []))

    classes, calls, callbacks, literals = set(), set(), set(), set()
    method_count = instruction_count = 0
    for dex in dexes:
        # DEX.get_methods() is the METHOD-ID reference table, whose entries
        # are MethodIdItem, NOT EncodedMethod. They have no get_instructions().
        # ClassDefItem.get_methods() yields actual EncodedMethod code bodies.
        class_definitions = dex.get_classes()
        for cls in class_definitions:
            classes.add(cls.get_name())
        for literal in dex.get_strings():
            if len(literals) >= MAX_STRINGS:
                raise SampleRejected("DEX string limit exceeded")
            literals.add(literal)
        for cls in class_definitions:
            for method in cls.get_methods():
                method_count += 1
                if method_count > MAX_CODE_METHODS:
                    raise SampleRejected("DEX method limit exceeded")
                name = method.get_name()
                if name in CALLBACKS:
                    callbacks.add(name)
                for instruction in method.get_instructions():
                    instruction_count += 1
                    if instruction_count > MAX_CODE_INSTRUCTIONS:
                        raise SampleRejected("DEX instruction limit exceeded")
                    if instruction.get_name().startswith("invoke-"):
                        ref = INVOKE.search(instruction.get_output() or "")
                        if ref:
                            owner, invoked = ref.groups()
                            calls.add((owner, invoked))
                            classes.add(owner)
    return feature_vector(schema, permissions=permissions, actions=actions,
                          classes=classes, calls=calls, callbacks=callbacks, literals=literals)


def recent_threatfox_sha256_iocs(path: Path) -> list[str]:
    """Read unique SHA-256 IOC values from a ThreatFox get_iocs response."""
    response = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(response, dict) or response.get("query_status") != "ok":
        raise ValueError("Invalid ThreatFox recent IOCs response")
    items = response.get("data")
    if not isinstance(items, list):
        raise ValueError("Missing ThreatFox IOC data")
    found, seen = [], set()
    for record in items:
        if not isinstance(record, dict):
            continue
        if str(record.get("ioc_type", "")).strip().lower() != "sha256_hash":
            continue
        digest = str(record.get("ioc") or "").strip().lower()
        if not SHA256.fullmatch(digest):
            raise ValueError("ThreatFox returned a malformed SHA-256 IOC")
        if digest not in seen:
            seen.add(digest)
            found.append(digest)
    return found


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_recent(path: Path, output: Path, max_samples: int = 20, *,
                   samples_dir: Path, analyzer=None,
                   enrichment_csv: Path | None = None):
    """Extract vectors only from separately staged, hash-matching local APK files.

    ThreatFox is an IOC feed and does not expose APK download bytes through
    get_iocs. This helper deliberately performs no sample-provider network calls.
    """
    if not 1 <= max_samples <= 20:
        raise ValueError("Sampling budget must be 1..20 APK attempts")
    if os.environ.get("THREATFOX_AI_TRAINING_APPROVED", "").strip().lower() != "true":
        raise PermissionError(
            "ThreatFox data is not approved for AI training; require Spamhaus prior written consent."
        )
    schema = schema_features()
    candidates = recent_threatfox_sha256_iocs(path)
    if enrichment_csv is None:
        enrichment_csv = Path(__file__).resolve().parents[1] / "data/enriched_threats.csv"
    enrichment = load_enrichment_cache(Path(enrichment_csv))
    verified = [digest for digest in candidates
                if has_complete_reputation(enrichment.get(digest, {}))]
    skipped = len(candidates) - len(verified)
    print(f"MLOps discovery: {len(verified)} reputation-qualified ThreatFox hashes; "
          f"skipped {skipped} without required HA evidence.", flush=True)

    if not samples_dir.is_dir():
        print("MLOps skipped: no separately authorized local APK sample directory was supplied.", flush=True)
        rows: list[list[int]] = []
        feature_metadata: list[dict[str, object]] = []
    else:
        rows = []
        feature_metadata = []
        attempts = 0
        failures: dict[str, int] = {}
        for digest in verified:
            if attempts >= max_samples or len(rows) >= min(10, max_samples):
                break
            attempts += 1
            sample = samples_dir / f"{digest}.apk"
            try:
                if not sample.is_file() or sample.is_symlink():
                    raise SampleRejected("No local APK file staged for this IOC")
                if sample.stat().st_size <= 0 or sample.stat().st_size > MAX_APK_BYTES:
                    raise SampleRejected("Local APK violates size limits")
                if file_sha256(sample) != digest:
                    raise SampleRejected("Local APK SHA-256 does not match ThreatFox IOC")
                vector = analyze_android_apk(sample, schema, analyzer=analyzer)
                if len(vector) != 215 or any(bit not in (0, 1) for bit in vector):
                    raise SampleRejected("Feature extractor returned a non-binary 215-bit vector")
                reputation = enrichment[digest]
                rows.append(vector)
                feature_metadata.append({
                    "sha256": digest,
                    "vt_malicious_count": int(reputation["vt_malicious_count"]),
                    "ha_threat_score": (
                        float(reputation["ha_threat_score"])
                        if str(reputation["ha_threat_score"]).strip().lower() not in ("", "not found")
                        else "Not Found"
                    ),
                    "ha_verdict": reputation["ha_verdict"],
                })
            except Exception as exc:
                cause = type(exc).__name__
                failures[cause] = failures.get(cause, 0) + 1
                print(f"MLOps skipped local candidate: {cause}", flush=True)

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(".part")
    try:
        temporary.write_text(json.dumps({
            "feature_rows": rows,
            "feature_metadata": feature_metadata,
        }, separators=(",", ":"), allow_nan=False) + "\n", encoding="utf-8")
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"MLOps RESULT: ThreatFox candidates={len(candidates)}; validated_local_apk_rows={len(rows)}; "
          f"target_rows={min(10, max_samples)}.", flush=True)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recent", type=Path, required=True,
                        help="ThreatFox get_iocs JSON response written by build_threatfox_hsb.py")
    parser.add_argument("--samples-dir", type=Path, required=True,
                        help="Separately authorized local directory containing <sha256>.apk files")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-samples", type=int, default=20)
    parser.add_argument("--enrichment-csv", type=Path,
                        default=Path(__file__).resolve().parents[1] / "data/enriched_threats.csv")
    args = parser.parse_args()
    extract_recent(args.recent, args.output, args.max_samples, samples_dir=args.samples_dir,
                   enrichment_csv=args.enrichment_csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
def load_enrichment_cache(path: Path) -> dict[str, dict[str, str]]:
    """Load provider metadata keyed by SHA-256; never infer a missing verdict."""
    if not path.is_file():
        return {}
    expected = {"sha256", "vt_malicious_count", "ha_threat_score", "ha_verdict"}
    with path.open("r", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if set(reader.fieldnames or ()) != expected:
            raise ValueError("Enrichment CSV header does not match the required schema")
        output = {}
        for row in reader:
            digest = str(row.get("sha256") or "").lower()
            if not SHA256.fullmatch(digest):
                raise ValueError("Enrichment CSV contains an invalid SHA-256")
            output[digest] = row
    return output


def has_complete_reputation(record: dict[str, str]) -> bool:
    """Apply the Hybrid Analysis fallback when VirusTotal is disabled (-1)."""
    try:
        vt_count = int(record["vt_malicious_count"])
        verdict = str(record["ha_verdict"]).strip().lower()
        try:
            ha_score = float(record["ha_threat_score"])
        except (TypeError, ValueError):
            ha_score = None
        if vt_count == -1:
            # With VT disabled, either HA score >=70 OR a malicious verdict is enough.
            return (ha_score is not None and ha_score >= 70.0) or verdict == "malicious"
        return (
            vt_count > 0
            and ha_score is not None
            and 0.0 <= ha_score <= 100.0
            and verdict == "malicious"
        )
    except (KeyError, TypeError, ValueError):
        return False


