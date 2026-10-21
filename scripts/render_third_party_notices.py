#!/usr/bin/env python3
"""Render a dependency-by-dependency third-party notice inventory from CycloneDX JSON."""
import argparse
import json
from pathlib import Path
from urllib.parse import quote

def comp_license(component):
    licenses = component.get("licenses") or []
    values = []
    for item in licenses:
        license_obj = item.get("license") or {}
        expr = item.get("expression")
        label = expr or license_obj.get("id") or license_obj.get("name")
        url = license_obj.get("url")
        if label:
            values.append(f"[{label}]({url})" if url else label)
    return "; ".join(sorted(set(values))) or "UNKNOWN — review required"

def comp_source(component):
    refs = component.get("externalReferences") or []
    preferred = []
    for ref in refs:
        kind = (ref.get("type") or "").lower()
        url = ref.get("url")
        if url and kind in {"vcs", "website", "distribution"}:
            preferred.append((0 if kind == "vcs" else 1, url))
    if preferred:
        return sorted(preferred)[0][1]
    purl = component.get("purl")
    if purl:
        return "Package URL: " + purl
    return "UNKNOWN — upstream source URL not published in SBOM metadata"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="CycloneDX aggregate JSON")
    parser.add_argument("--output", required=True, help="Markdown output path")
    parser.add_argument("--strict", action="store_true", help="fail if any component lacks license or source metadata")
    args = parser.parse_args()
    bom = json.loads(Path(args.input).read_text(encoding="utf-8"))
    components = bom.get("components") or []
    components = sorted(components, key=lambda c: (c.get("name", "").lower(), c.get("version", "")))
    unknown = []
    lines = [
        "# Third-party dependency notices",
        "",
        f"Generated from the CycloneDX SBOM by `scripts/render_third_party_notices.py`. Components: {len(components)}.",
        "",
        "Regenerate this file with the CI SBOM refresh workflow; do not hand-edit dependency rows.",
        "",
        "| Component | Version | Declared licence | Upstream source / package reference |",
        "|---|---:|---|---|",
    ]
    for component in components:
        name = component.get("name") or "(unnamed component)"
        version = component.get("version") or "unspecified"
        lic = comp_license(component)
        source = comp_source(component)
        if lic.startswith("UNKNOWN") or source.startswith("UNKNOWN"):
            unknown.append(f"{name}@{version}: licence={lic}; source={source}")
        lines.append(f"| {name.replace('|', '\\|')} | {version.replace('|', '\\|')} | {lic.replace('|', '\\|')} | {source.replace('|', '\\|')} |")
    lines.extend(["", f"Metadata completeness: {len(components) - len(unknown)}/{len(components)} components have both a declared licence and a source/package reference.", ""])
    if unknown:
        lines.extend(["## Metadata requiring manual review", ""])
        lines.extend(f"- {item}" for item in unknown)
        lines.append("")
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text("\n".join(lines), encoding="utf-8")
    print(f"Rendered {len(components)} components; {len(unknown)} need metadata review.")
    if args.strict and unknown:
        raise SystemExit(1)

if __name__ == "__main__":
    main()
