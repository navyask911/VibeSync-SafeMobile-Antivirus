#!/usr/bin/env python3
"""Guard Play release version codes without blocking CI-only maintenance.

- A signed Play release must strictly exceed every previous Play app release.
- CI-only changes may reuse the already-published app code IF the *entire app/*
  source tree is byte-for-byte the same as its tagged release.
- Signed malware-hash-database tags never count as Android app releases.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_GRADLE = ROOT / "app" / "build.gradle.kts"
PATTERN = re.compile(r"\bversionCode\s*=\s*(\d+)")
APP_RELEASE_TAG = re.compile(r"^safemobile-v\d+\.\d+\.\d+-code(?P<code>\d+)-run\d+$")


def code_from_text(value: str):
    match = PATTERN.search(value)
    return int(match.group(1)) if match else None


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def validate(release: bool = False) -> None:
    try:
        current = code_from_text(APP_GRADLE.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"Cannot read app Gradle file: {error}") from error
    if current is None:
        raise ValueError("versionCode was not found in app/build.gradle.kts")
    try:
        tags = run("git", "tag", "--list").splitlines()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError("Git tags unavailable; checkout requires fetch-depth: 0") from error
    tagged = []
    for tag in tags:
        release_tag = APP_RELEASE_TAG.fullmatch(tag)
        if release_tag is None:
            continue  # A signed hash database is NOT an Android app release.
        try:
            tagged_gradle = run("git", "show", f"{tag}:app/build.gradle.kts")
        except subprocess.CalledProcessError as error:
            raise ValueError(f"Tagged Play release has no Gradle build config: {tag}") from error
        code = code_from_text(tagged_gradle)
        if code != int(release_tag.group("code")):
            raise ValueError(f"Inconsistent Play release tag/build versionCode: {tag}")
        tagged.append((code, tag))
    maximum = max((code for code, _ in tagged), default=0)
    if current > maximum:
        print(f"Version-code guard passed: current={current}, prior Play max={maximum}.")
        return
    if current == maximum and not release:
        # CI-only changes need not bump Play versionCode, but this is allowed
        # exclusively when the *whole app/* tree matches an already signed
        # app release. Any changed Android resource or binary source fails.
        try:
            working_app_tree = run("git", "rev-parse", "HEAD:app")
            for code, tag in tagged:
                if code == maximum and run("git", "rev-parse", f"{tag}:app") == working_app_tree:
                    print(f"Version-code guard passed: unchanged app tree at published version {current}.")
                    return
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError("Unable to verify unchanged Android application tree") from error
    owner = next((tag for code, tag in tagged if code == maximum), "none")
    requirement = "must exceed" if release or current < maximum else "must exceed, or keep identical app tree as"
    raise ValueError(
        f"current {current} {requirement} published Play maximum {maximum} "
        f"(tag {owner}); app changes require a new Play versionCode"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true",
                        help="Require a strictly greater versionCode for new signed Play releases")
    args = parser.parse_args()
    try:
        validate(release=args.release)
    except ValueError as error:
        print(f"Version-code guard FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
