#!/usr/bin/env python3
"""Verify the post-merge v1.6.0 APK, downloaded ML assets, EICAR and bundled YARA rules."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "app/src/main/assets"
MODEL_SHA256 = "8b66adaf01a939c26d5a756e66f53fe0d6e85e1a06ec97166579138c6ce47061"
SCHEMA_SHA256 = "ffb386be14adf8c0af1bb96032e5485fcc8fd5b401a24488c5896e2d5ea425ac"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def fail(message):
    print("Release verification FAILED: " + message, file=sys.stderr)
    raise SystemExit(1)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=Path)
    args = parser.parse_args()

    model_path = ASSETS / "model.tflite"
    schema_path = ASSETS / "feature_schema.json"
    if not model_path.is_file() or not schema_path.is_file():
        fail("Gradle did not download both ML release assets into app/src/main/assets.")

    model = model_path.read_bytes()
    schema_raw = schema_path.read_bytes()
    if len(model) != 18584 or model[4:8] != b"TFL3" or sha256(model) != MODEL_SHA256:
        fail("Downloaded model size, TFL3 header or SHA-256 does not match v1.0.1-model.")
    schema = json.loads(schema_raw.decode("utf-8"))
    if (list(schema.keys()) != [str(i) for i in range(215)] or
            len(set(schema.values())) != 215 or sha256(schema_raw) != SCHEMA_SHA256):
        fail("Downloaded feature schema is not the exact ordered 215-feature release.")

    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True
    ).stdout.splitlines()
    forbidden = {
        "app/src/main/assets/model.tflite",
        "app/src/main/assets/malware_model.tflite",
        "app/src/main/assets/feature_schema.json",
        "app/src/main/assets/malware_model.json",
    }
    if not forbidden.isdisjoint(set(tracked)):
        fail("ML release assets are tracked in the Android app repository.")

    matcher = (ROOT / "app/src/main/java/com/vibesync/antivirus/core/engine/hash/HashMatcher.kt").read_text(encoding="utf-8")
    if EICAR_SHA256 not in matcher:
        fail("Pinned EICAR SHA-256 is missing from HashMatcher.")

    yara_dir = ASSETS / "yara"
    yara_files = sorted(list(yara_dir.glob("*.yar")) + list(yara_dir.glob("*.yara")))
    if not yara_files or not any("rule " in p.read_text(encoding="utf-8", errors="replace") for p in yara_files):
        fail("No non-empty YARA rule source is present under app/src/main/assets/yara/.")

    apk = args.apk if args.apk.is_absolute() else ROOT / args.apk
    if not apk.is_file():
        fail("Debug APK does not exist: " + str(apk))
    try:
        with zipfile.ZipFile(apk) as archive:
            names = set(archive.namelist())
            required = {
                "assets/model.tflite",
                "assets/feature_schema.json",
                "assets/yara/safemobile_android_dex.yar",
            }
            missing = required - names
            if missing:
                fail("Debug APK is missing packaged assets: " + ", ".join(sorted(missing)))
            if sha256(archive.read("assets/model.tflite")) != MODEL_SHA256:
                fail("Packaged APK model checksum differs from the verified download.")
            if sha256(archive.read("assets/feature_schema.json")) != SCHEMA_SHA256:
                fail("Packaged APK feature schema checksum differs from the verified download.")
    except zipfile.BadZipFile:
        fail("Cannot read generated debug APK as a zip archive.")

    print("Release verification passed: clean debug APK contains SHA-pinned ML assets; EICAR and YARA rules are present; ML files are not Git-tracked.")


if __name__ == "__main__":
    main()
