#!/usr/bin/env python3
"""Verify packaged native ELF segments and APK zip alignment for Android 16 KB devices."""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PAGE_SIZE = 16 * 1024
NDK_VERSION = "28.2.13676358"
REQUIRED_RUNTIME_LIBRARY = "libtensorflowlite_jni.so"


def locate_readelf() -> str:
    direct = shutil.which("llvm-readelf")
    if direct:
        return direct
    roots: list[Path] = []
    ndk_home = os.environ.get("ANDROID_NDK_HOME")
    if ndk_home:
        roots.append(Path(ndk_home))
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk_root:
        roots.append(Path(sdk_root) / "ndk" / NDK_VERSION)
    for root in roots:
        candidates = sorted(root.glob("toolchains/llvm/prebuilt/*/bin/llvm-readelf"))
        if candidates and candidates[-1].is_file():
            return str(candidates[-1])
    raise RuntimeError(
        f"llvm-readelf not found. Install NDK {NDK_VERSION} and set ANDROID_NDK_HOME."
    )


def locate_zipalign() -> str:
    sdk_root = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    candidates: list[Path] = []
    if sdk_root:
        candidates.extend((Path(sdk_root) / "build-tools").glob("*/zipalign"))
    candidates = sorted(path for path in candidates if path.is_file())
    if candidates:
        return str(candidates[-1])
    direct = shutil.which("zipalign")
    if direct:
        return direct
    raise RuntimeError("zipalign not found. Android Build-Tools 35.0.0 or later is required.")


def inspect_elf(readelf: str, artifact: Path, entry: str, data: bytes, temp_root: Path) -> None:
    extracted = temp_root / (artifact.stem + "_" + entry.replace("/", "_"))
    extracted.write_bytes(data)
    result = subprocess.run(
        [readelf, "-lW", str(extracted)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"{artifact.name}!/{entry}: llvm-readelf failed: {result.stderr.strip()}")
    load_segments = [
        line for line in result.stdout.splitlines()
        if line.lstrip().startswith("LOAD ")
    ]
    if not load_segments:
        raise RuntimeError(f"{artifact.name}!/{entry}: no ELF PT_LOAD segments were found.")
    invalid = []
    for line in load_segments:
        fields = line.split()
        try:
            alignment = int(fields[-1], 16)
        except (IndexError, ValueError) as error:
            raise RuntimeError(f"{artifact.name}!/{entry}: cannot parse PT_LOAD alignment: {line}") from error
        if alignment < PAGE_SIZE or alignment % PAGE_SIZE != 0:
            invalid.append((alignment, line.strip()))
    if invalid:
        detail = "; ".join(f"p_align=0x{value:x} [{line}]" for value, line in invalid)
        raise RuntimeError(f"{artifact.name}!/{entry}: 16 KB ELF alignment failed: {detail}")


def check_artifact(path: Path, readelf: str, zipalign: str, temp_root: Path) -> int:
    if not path.is_file():
        raise RuntimeError(f"Artifact not found: {path}")
    if path.suffix.lower() not in {".apk", ".aab"}:
        raise RuntimeError(f"Unsupported artifact type: {path}")
    with zipfile.ZipFile(path, "r") as archive:
        native_entries = sorted(
            name for name in archive.namelist()
            if name.endswith(".so") and not name.endswith("/")
        )
        if not native_entries:
            raise RuntimeError(f"{path}: no native shared libraries were packaged.")
        if not any(Path(name).name == REQUIRED_RUNTIME_LIBRARY for name in native_entries):
            raise RuntimeError(
                f"{path}: LiteRT {REQUIRED_RUNTIME_LIBRARY} was not packaged."
            )
        for entry in native_entries:
            inspect_elf(readelf, path, entry, archive.read(entry), temp_root)
    if path.suffix.lower() == ".apk":
        result = subprocess.run(
            [zipalign, "-c", "-P", "16", "-v", "4", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"{path}: 16 KB APK zip alignment failed.\n"
                f"{result.stdout[-2000:]}\n{result.stderr[-2000:]}"
            )
    print(f"16 KB aligned: {path} ({len(native_entries)} native libraries)")
    return len(native_entries)


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: check_16kb_alignment.py <APK-or-AAB> [...]", file=sys.stderr)
        return 2
    artifacts: list[Path] = []
    for argument in sys.argv[1:]:
        matches = glob.glob(argument)
        artifacts.extend(Path(match) for match in matches) if matches else artifacts.append(Path(argument))
    try:
        readelf = locate_readelf()
        zipalign = locate_zipalign()
        checked = 0
        with tempfile.TemporaryDirectory(prefix="safemobile-16kb-") as directory:
            temp_root = Path(directory)
            for artifact in artifacts:
                checked += check_artifact(artifact, readelf, zipalign, temp_root)
        print(f"16 KB validation passed: {len(artifacts)} artifact(s), {checked} native libraries.")
        return 0
    except (OSError, RuntimeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"16 KB validation FAILED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
