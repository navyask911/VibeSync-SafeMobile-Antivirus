#!/usr/bin/env python3
"""Opt-in MalwareBazaar APK -> frozen Drebin-215 feature vectors.

Defensive static inspection ONLY: never execute APK code, upload samples or store
sample ZIP/APK bytes in GitHub Actions artifacts. Failures are per-sample and do
not change the separately signed hash database. Run in the ephemeral CI runner.
"""
from __future__ import annotations

import argparse
from io import BytesIO
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "app/src/main/assets/feature_schema.json"
SCHEMA_SHA256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
INVOKE = re.compile(r"(L[A-Za-z0-9_/$-]+;)->([A-Za-z0-9_$<>]+)\(")
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
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
        from androguard.misc import AnalyzeAPK  # imports only in optional CI job
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
        for cls in dex.get_classes():
            classes.add(cls.get_name())
        for literal in dex.get_strings():
            if len(literals) >= MAX_STRINGS:
                raise SampleRejected("DEX string limit exceeded")
            literals.add(literal)
        for method in dex.get_methods():
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


def recent_apk_digests(path: Path) -> list[str]:
    response = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(response, dict) or response.get("query_status") != "ok":
        raise ValueError("Invalid MalwareBazaar recent detections response")
    items = response.get("data")
    if not isinstance(items, list):
        raise ValueError("Missing recent detections")
    found, seen = [], set()
    for record in items:
        if not isinstance(record, dict):
            continue
        digest = str(record.get("sha256_hash", "")).lower()
        if not SHA256.fullmatch(digest) or digest in seen:
            continue
        file_name = str(record.get("file_name") or "").lower()
        file_type = str(record.get("file_type") or "").lower()
        mime = str(record.get("file_type_mime") or "").lower()
        # Avoid unnecessary downloads of Windows EXEs, PDFs and non-APK malware.
        if (file_type not in ("apk", "android") and not file_name.endswith(".apk")
                and mime not in ("application/vnd.android.package-archive", "application/x-android-package")):
            continue
        seen.add(digest)
        found.append(digest)
    return found


def encrypted_zip_to_apk(contents: bytes, digest: str) -> bytes:
    """Read one AES ZIP entry in memory, enforce size/hash; do not extractall."""
    if len(contents) > MAX_DOWNLOAD_BYTES or not contents.startswith(b"PK\x03\x04"):
        raise SampleRejected("Not a bounded encrypted sample ZIP")
    import pyzipper
    with pyzipper.AESZipFile(BytesIO(contents)) as archive:
        members = [item for item in archive.infolist() if not item.is_dir()]
        if len(members) != 1:
            raise SampleRejected("Expected one malware sample per ZIP")
        entry = members[0]
        if (entry.file_size <= 0 or entry.file_size > MAX_APK_BYTES
                or entry.is_dir() or ((entry.external_attr >> 16) & 0o170000) == 0o120000):
            raise SampleRejected("ZIP member violates resource/symlink limits")
        with archive.open(entry, pwd=b"infected") as source:
            apk = source.read(MAX_APK_BYTES + 1)
        if len(apk) != entry.file_size or len(apk) > MAX_APK_BYTES:
            raise SampleRejected("APK decompression length mismatch")
    if hashlib.sha256(apk).hexdigest() != digest:
        raise SampleRejected("Sample SHA-256 does not match MalwareBazaar metadata")
    with zipfile.ZipFile(BytesIO(apk)) as container:
        names = set(container.namelist())
        if "AndroidManifest.xml" not in names or "classes.dex" not in names:
            raise SampleRejected("Not a DEX-backed Android APK")
    return apk


def download_sample(session, api_key: str, digest: str) -> bytes:
    with session.post(
        MALWAREBAZAAR_URL, headers={"Auth-Key": api_key, "User-Agent": "SafeMobile-Defensive-Research/1.0"},
        data={"query": "get_file", "sha256_hash": digest},
        stream=True, timeout=(12, 45), allow_redirects=False,
    ) as response:
        response.raise_for_status()
        if response.headers.get("Content-Length", "").isdigit() and (
                int(response.headers["Content-Length"]) > MAX_DOWNLOAD_BYTES):
            raise SampleRejected("Downloaded ZIP exceeds byte budget")
        out = BytesIO()
        for chunk in response.iter_content(chunk_size=65536):
            if not chunk:
                continue
            if out.tell() + len(chunk) > MAX_DOWNLOAD_BYTES:
                raise SampleRejected("Downloaded ZIP exceeds byte budget")
            out.write(chunk)
        return out.getvalue()


def extract_recent(path: Path, output: Path, max_samples: int = 20, *, session=None, analyzer=None):
    """Only 10..20 attempts; sample errors never affect separate signed DB sync."""
    if not 10 <= max_samples <= 20:
        raise ValueError("Sampling budget must be 10..20 APK attempts")
    schema = schema_features()
    digests = recent_apk_digests(path)[:max_samples]
    rows = []
    if digests:
        key = os.environ.get("MALWAREBAZAAR_AUTH_KEY", "")
        if not key:
            raise ValueError("MalwareBazaar authorization not available")
        if session is None:
            import requests
            session = requests.Session()
        for digest in digests:
            try:
                zip_bytes = download_sample(session, key, digest)
                apk = encrypted_zip_to_apk(zip_bytes, digest)
                del zip_bytes
                with tempfile.TemporaryDirectory(prefix="safemobile-ml-apk-") as directory:
                    target = Path(directory) / "sample.apk"
                    target.write_bytes(apk)
                    del apk
                    vector = analyze_android_apk(target, schema, analyzer=analyzer)
                if len(vector) != 215 or any(type(bit) is not int or bit not in (0, 1) for bit in vector):
                    raise SampleRejected("Extractor produced an invalid feature vector")
                rows.append(vector)
            except Exception as exc:
                # Log only the exception class, never credentials/sample content/digests.
                print(f"Skipped unreadable/non-APK candidate ({type(exc).__name__})")
                continue
    output.parent.mkdir(parents=True, exist_ok=True)
    tmp = output.with_suffix(".part")
    try:
        tmp.write_text(json.dumps({"feature_rows": rows}, separators=(",", ":")) + "\n", encoding="utf-8")
        tmp.replace(output)
    finally:
        tmp.unlink(missing_ok=True)
    print(f"Reviewed {len(digests)} APK candidates; {len(rows)} validated Drebin-215 rows.")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recent", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-samples", type=int, default=20)
    args = parser.parse_args()
    extract_recent(args.recent, args.output, args.max_samples)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
