#!/usr/bin/env python3
"""Require monotonically increasing Play app codes; ignore hash DB signature release tags."""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_GRADLE = ROOT / "app" / "build.gradle.kts"
PATTERN = re.compile(r"\bversionCode\s*=\s*(\d+)")
APP_RELEASE_TAG = re.compile(r"^safemobile-v\d+\.\d+\.\d+-code(?P<code>\d+)-run\d+$")

def code_from_text(text: str):
    match = PATTERN.search(text)
    return int(match.group(1)) if match else None

def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.DEVNULL)

try:
    current = code_from_text(APP_GRADLE.read_text(encoding="utf-8"))
except OSError as exc:
    print(f"Version-code guard: cannot read app Gradle file: {exc}", file=sys.stderr)
    sys.exit(2)
if current is None:
    print("Version-code guard: versionCode was not found in app/build.gradle.kts.", file=sys.stderr)
    sys.exit(2)

try:
    tags = run("git", "tag", "--list").splitlines()
except (OSError, subprocess.CalledProcessError):
    print("Version-code guard: Git tag history is unavailable; fetch full history with fetch-depth: 0.", file=sys.stderr)
    sys.exit(2)

tagged = []
for tag in tags:
    release = APP_RELEASE_TAG.fullmatch(tag)
    if release is None:
        continue  # Hash DB signatures, temporary tags and CI tags are not Play app releases.
    try:
        text = run("git", "show", f"{tag}:app/build.gradle.kts")
    except subprocess.CalledProcessError:
        continue
    value = code_from_text(text)
    if value is None or value != int(release.group("code")):
        print(f"Version-code guard: inconsistent app-release tag {tag}.", file=sys.stderr)
        sys.exit(2)
    tagged.append((value, tag))

maximum = max((value for value, _ in tagged), default=0)
if current <= maximum:
    who = max(tagged, default=(0, "none"), key=lambda item: item[0])[1]
    print(f"Version-code guard FAILED: current {current} must exceed tagged maximum {maximum} (tag {who}).", file=sys.stderr)
    sys.exit(1)
print(f"Version-code guard passed: current={current}, tagged_max={maximum}, tags_checked={len(tagged)}.")
