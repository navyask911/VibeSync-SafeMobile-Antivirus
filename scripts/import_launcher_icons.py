#!/usr/bin/env python3
"""Safely import branded Android launcher PNGs from the repository-root ZIP.

Only selected, validated PNG/XML resources are copied. Archive paths are never
extracted wholesale; every destination is constructed from an allow-list.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import struct
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path, PurePosixPath

DENSITIES = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_MEMBER = 12 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

class ImportErrorSafe(Exception):
    pass

def safe_parts(name: str) -> tuple[str, ...]:
    p = PurePosixPath(name)
    if p.is_absolute() or "\\" in name or any(x in ("", ".", "..") for x in p.parts):
        raise ImportErrorSafe(f"Unsafe ZIP entry path: {name!r}")
    if any(ord(ch) < 32 for ch in name):
        raise ImportErrorSafe(f"Control character in ZIP path: {name!r}")
    return p.parts

def read_member(z: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size <= 0 or info.file_size > MAX_MEMBER:
        raise ImportErrorSafe(f"Unexpected file size for {info.filename}: {info.file_size}")
    if info.compress_size == 0 or info.file_size / max(1, info.compress_size) > 300:
        raise ImportErrorSafe(f"Suspicious compression ratio for {info.filename}")
    data = z.read(info)
    if len(data) != info.file_size:
        raise ImportErrorSafe(f"Truncated ZIP member: {info.filename}")
    return data

def png_size(data: bytes, label: str) -> tuple[int, int]:
    if len(data) < 24 or data[:8] != PNG_SIGNATURE or data[12:16] != b"IHDR":
        raise ImportErrorSafe(f"Not a valid PNG/IHDR: {label}")
    width, height = struct.unpack(">II", data[16:24])
    if not (1 <= width <= 4096 and 1 <= height <= 4096):
        raise ImportErrorSafe(f"Invalid PNG dimensions {width}x{height}: {label}")
    return width, height

def match_density(entries, density: str, filename: str):
    component = f"mipmap-{density}"
    candidates = [e for e in entries if not e.is_dir()
                  and PurePosixPath(e.filename).name == filename
                  and component in safe_parts(e.filename)]
    if not candidates:
        raise ImportErrorSafe(f"ZIP is missing {component}/{filename}")
    candidates.sort(key=lambda e: (len(safe_parts(e.filename)), e.filename))
    return candidates

def choose_single(entries, predicate, label: str):
    candidates = [e for e in entries if not e.is_dir() and predicate(e)]
    if not candidates:
        raise ImportErrorSafe(f"ZIP is missing {label}")
    if len(candidates) == 1:
        return candidates[0]
    preferred = [e for e in candidates
                 if re.search(r"(play.?store|store.?icon|google.?play)", PurePosixPath(e.filename).name, re.I)]
    if len(preferred) == 1:
        return preferred[0]
    raise ImportErrorSafe(f"ZIP has ambiguous {label}: {[e.filename for e in candidates]}")

def copy_staged(staged: Path, relative: str, data: bytes):
    target = staged / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)

def existing_resource(root: Path, kind: str, name: str) -> bool:
    res = root / "app/src/main/res"
    if kind in ("drawable", "mipmap"):
        return any((res / d / (name + ext)).is_file()
                   for d in res.iterdir() if d.is_dir() and d.name.startswith(kind)
                   for ext in (".png", ".webp", ".jpg", ".jpeg", ".xml", ".avif"))
    if kind == "color":
        for values in res.glob("values*"):
            if not values.is_dir():
                continue
            for xml in values.glob("*.xml"):
                try:
                    node = ET.parse(xml).getroot()
                except ET.ParseError:
                    continue
                if any(child.tag == "color" and child.attrib.get("name") == name for child in node):
                    return True
    return False

def import_adaptive(z: zipfile.ZipFile, entries, root: Path, staged: Path) -> list[str]:
    changed = []
    adaptive_entries = [e for e in entries if not e.is_dir()
                        and "mipmap-anydpi-v26" in safe_parts(e.filename)
                        and PurePosixPath(e.filename).name in ("ic_launcher.xml", "ic_launcher_round.xml")]
    if not adaptive_entries:
        print("No adaptive icon XML in ZIP; existing adaptive launcher icon retained.")
        return changed
    for info in adaptive_entries:
        data = read_member(z, info)
        try:
            node = ET.fromstring(data)
        except ET.ParseError as exc:
            print(f"WARNING: invalid adaptive XML {info.filename}: {exc}; retained existing.")
            continue
        if node.tag.split("}")[-1] != "adaptive-icon":
            print(f"WARNING: {info.filename} is not an adaptive-icon; retained existing.")
            continue
        refs = []
        valid = True
        for child in node.iter():
            drawable = child.attrib.get(ANDROID_NS + "drawable", "")
            m = re.fullmatch(r"@(drawable|mipmap|color)/([A-Za-z0-9_]+)", drawable)
            if m:
                refs.append((m.group(1), m.group(2)))
            elif drawable.startswith("@"):
                print(f"WARNING: unsupported adaptive reference {drawable}; retained existing.")
                valid = False
                break
        if not valid or not refs:
            continue
        resources = []
        all_ok = True
        for kind, name in refs:
            if existing_resource(root, kind, name):
                continue
            if kind in ("drawable", "mipmap"):
                candidates = [e for e in entries if not e.is_dir()
                              and PurePosixPath(e.filename).name.rsplit(".", 1)[0] == name
                              and any(part == kind or part.startswith(kind + "-") for part in safe_parts(e.filename))]
                if not candidates:
                    all_ok = False
                    break
                for res in candidates:
                    parts = safe_parts(res.filename)
                    qualifier = next((p for p in parts if p == kind or p.startswith(kind + "-")), kind)
                    ext = Path(parts[-1]).suffix.lower()
                    if ext not in (".png", ".webp", ".jpg", ".jpeg", ".xml"):
                        all_ok = False
                        break
                    resources.append((f"app/src/main/res/{qualifier}/{name}{ext}", read_member(z, res)))
            else:
                color_nodes = []
                for res in entries:
                    if res.is_dir() or PurePosixPath(res.filename).name not in ("colors.xml", "color.xml"):
                        continue
                    try:
                        values = ET.fromstring(read_member(z, res))
                    except ET.ParseError:
                        continue
                    color_nodes.extend(c for c in values if c.tag == "color" and c.attrib.get("name") == name)
                if not color_nodes:
                    all_ok = False
                    break
                values_root = ET.Element("resources")
                values_root.append(color_nodes[0])
                payload = ET.tostring(values_root, encoding="utf-8", xml_declaration=True)
                resources.append((f"app/src/main/res/values/launcher_imported_{name}.xml", payload))
        if not all_ok:
            print(f"WARNING: unresolved resources in {info.filename}; retained existing adaptive icon.")
            continue
        for relative, payload in resources:
            copy_staged(staged, relative, payload)
            changed.append(relative)
        filename = PurePosixPath(info.filename).name
        relative = f"app/src/main/res/mipmap-anydpi-v26/{filename}"
        copy_staged(staged, relative, data)
        changed.append(relative)
        print(f"Accepted adaptive icon: {filename}")
    return changed

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    archives = [root / "app_icons.zip", root / "app_icons.zip.zip"]
    found = [p for p in archives if p.is_file()]
    if len(found) != 1:
        raise ImportErrorSafe("Expected exactly one root archive: app_icons.zip or app_icons.zip.zip")
    archive = found[0]
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ImportErrorSafe(f"Icon archive too large: {archive.stat().st_size} bytes")
    total = 0
    copied = []
    hashes = {}
    with tempfile.TemporaryDirectory(prefix="safemobile-icon-import-", dir=args.scratch) as temp:
        staged = Path(temp)
        with zipfile.ZipFile(archive) as z:
            entries = z.infolist()
            if len(entries) > 300:
                raise ImportErrorSafe("Too many archive entries")
            for entry in entries:
                safe_parts(entry.filename)
                if entry.is_dir():
                    continue
                total += entry.file_size
                if entry.file_size > MAX_MEMBER or total > MAX_TOTAL:
                    raise ImportErrorSafe("Archive exceeds bounded uncompressed size")
            selected = []
            for density, expected in DENSITIES.items():
                for filename in ("ic_launcher.png", "ic_launcher_round.png"):
                    candidates = match_density(entries, density, filename)
                    data = [read_member(z, e) for e in candidates]
                    if any(d != data[0] for d in data[1:]):
                        raise ImportErrorSafe(f"Conflicting duplicate {density}/{filename} entries")
                    dimensions = png_size(data[0], filename)
                    if dimensions != (expected, expected):
                        raise ImportErrorSafe(f"{density}/{filename}: expected {expected}x{expected}, got {dimensions}")
                    selected.append((f"app/src/main/res/mipmap-{density}/{filename}", data[0]))
            store = choose_single(entries, lambda e: e.filename.lower().endswith(".png")
                                  and png_size(read_member(z, e), e.filename) == (512, 512),
                                  "a unique 512x512 Play Store PNG")
            selected.append(("docs/assets/safemobile-playstore-icon.png", read_member(z, store)))
            for relative, data in selected:
                copy_staged(staged, relative, data)
                copied.append(relative)
                hashes[relative] = hashlib.sha256(data).hexdigest()
            copied.extend(import_adaptive(z, entries, root, staged))
            for relative in copied:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(staged / relative, target)
                hashes[relative] = hashlib.sha256((staged / relative).read_bytes()).hexdigest()
    report = {
        "archive_path": archive.relative_to(root).as_posix(),
        "copied_files": copied,
        "play_store_icon": "docs/assets/safemobile-playstore-icon.png",
        "adaptive_icons_updated": [p for p in copied if "mipmap-anydpi-v26" in p],
        "sha256": hashes,
        "density_dimensions": {k: [v, v] for k, v in DENSITIES.items()}
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("ICON_ARCHIVE_TO_REMOVE=" + report["archive_path"])

if __name__ == "__main__":
    try:
        main()
    except (ImportErrorSafe, OSError, zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        raise SystemExit("SAFE STOP: " + str(exc))
