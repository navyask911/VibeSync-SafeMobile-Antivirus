#!/usr/bin/env python3
"""Guard Play release version codes without blocking CI-only maintenance.

- A signed Play release must strictly exceed every previous Play app release.
- CI-only changes may reuse an already-published app version ONLY when every
  release-relevant app/* file is byte-for-byte identical to a signed tag.
  JVM/instrumented test source changes (app/src/test/ and app/src/androidTest/)
  are explicitly excluded because they never ship in the Play AAB.
- Signed malware-hash-database tags never count as Android app releases.
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_GRADLE = ROOT / "app" / "build.gradle.kts"
PATTERN = re.compile(r"\bversionCode\s*=\s*(\d+)")
APP_RELEASE_TAG = re.compile(r"^safemobile-v\d+\.\d+\.\d+-code(?P<code>\d+)-run\d+$")
CANONICAL_APP_RELEASE_TAG = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")


def code_from_text(value: str):
    match = PATTERN.search(value)
    return int(match.group(1)) if match else None


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()


def validate(release: bool = False, allow_pr_version_reuse: bool = False) -> None:
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
        canonical_tag = CANONICAL_APP_RELEASE_TAG.fullmatch(tag)
        if release_tag is None and canonical_tag is None:
            continue  # Ignore non-app tags such as model and hash-database releases.
        try:
            tagged_gradle = run("git", "show", f"{tag}:app/build.gradle.kts")
        except subprocess.CalledProcessError as error:
            raise ValueError(f"Tagged Play release has no Gradle build config: {tag}") from error
        code = code_from_text(tagged_gradle)
        if code is None:
            raise ValueError(f"Tagged Play release has no versionCode: {tag}")
        if release_tag is not None and code != int(release_tag.group("code")):
            raise ValueError(f"Inconsistent Play release tag/build versionCode: {tag}")
        if canonical_tag is not None:
            version_match = re.search(r'\bversionName\s*=\s*"([^"]+)"', tagged_gradle)
            tagged_version = version_match.group(1) if version_match is not None else None
            # Historical release metadata: the v1.6.4 tag points at the 1.6.5
            # Play build (versionCode 20261131). Preserve this exact legacy mapping;
            # all newly created canonical tags must still match their Gradle version.
            legacy_v164_alias = (
                tag == "v1.6.4" and tagged_version == "1.6.5" and code == 20261131
            )
            if tagged_version != canonical_tag.group("version") and not legacy_v164_alias:
                raise ValueError(f"Inconsistent canonical Play release tag/build versionName: {tag}")
        tagged.append((code, tag))
    maximum = max((code for code, _ in tagged), default=0)
    if allow_pr_version_reuse:
        if release:
            raise ValueError("PR version reuse cannot be combined with --release")
        if (os.environ.get("GITHUB_EVENT_NAME") != "pull_request" or
                os.environ.get("GITHUB_HEAD_REF") != "feat/ui-polish-v1.4.1"):
            raise ValueError("PR version reuse is restricted to the feat/ui-polish-v1.4.1 pull request")
        if current == maximum:
            owner = next((tag for code, tag in tagged if code == maximum), "none")
            print(
                f"PR validation only: allowing source changes at published versionCode {current} "
                f"(tag {owner}). A signed release still requires a strictly greater versionCode."
            )
            return
    if current > maximum:
        print(f"Version-code guard passed: current={current}, prior Play max={maximum}.")
        return
    if current == maximum and not release:
        # Only source sets that Android excludes from the signed APK/AAB may
        # change without incrementing the already-published versionCode.
        # All production code, resources, assets, Gradle config and manifests
        # MUST continue matching a signed release tag byte-for-byte.
        try:
            for code, tag in tagged:
                if code != maximum:
                    continue
                differences = run("git", "diff", "--name-only", "HEAD", tag, "--", "app")
                changed_files = differences.splitlines()
                shipped = [path for path in changed_files if not (
                    path.startswith("app/src/androidTest/") or
                    path.startswith("app/src/test/")
                )]
                if not shipped:
                    print(f"Version-code guard passed: signed app assets unchanged at published version {current}; only non-shipping tests may differ.")
                    return
        except (OSError, subprocess.CalledProcessError) as error:
            raise ValueError("Unable to compare shipping app sources with published release") from error
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
    parser.add_argument("--allow-pr-version-reuse", action="store_true",
                        help="Allow the published versionCode only for the feat/ui-polish-v1.4.1 PR validation run; never for signed releases")
    args = parser.parse_args()
    try:
        validate(release=args.release, allow_pr_version_reuse=args.allow_pr_version_reuse)
    except ValueError as error:
        print(f"Version-code guard FAILED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
