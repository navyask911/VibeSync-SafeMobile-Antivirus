#!/usr/bin/env python3
"""Render direct and transitive dependency notice rows from a CycloneDX JSON SBOM."""
import argparse
import json
from pathlib import Path


def comp_license(component):
    values = []
    for item in component.get("licenses") or []:
        license_obj = item.get("license") or {}
        label = item.get("expression") or license_obj.get("id") or license_obj.get("name")
        url = license_obj.get("url")
        if label:
            values.append(f"[{label}]({url})" if url else label)
    return "; ".join(sorted(set(values))) or "UNKNOWN — review required"


def comp_source_url(component):
    """Return an upstream URL, never silently substituting a PURL for a source URL."""
    preferred = []
    for ref in component.get("externalReferences") or []:
        kind = (ref.get("type") or "").lower()
        url = ref.get("url")
        if url and kind in {"vcs", "website", "distribution"}:
            priority = 0 if kind == "vcs" else 1
            preferred.append((priority, url))
    return sorted(preferred)[0][1] if preferred else "UNKNOWN — upstream source URL not published in SBOM metadata"


def cell(value):
    return str(value).replace("|", "&#124;").replace("\n", " ")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="CycloneDX aggregate JSON")
    parser.add_argument("--output", required=True, help="Markdown output path")
    parser.add_argument("--strict", action="store_true", help="fail if a component lacks a declared licence or upstream source URL")
    args = parser.parse_args()
    bom = json.loads(Path(args.input).read_text(encoding="utf-8"))
    components = sorted(
        bom.get("components") or [],
        key=lambda c: ((c.get("name") or "").lower(), c.get("version") or ""),
    )
    unknown = []
    lines = [
        "# Third-party dependency notices",
        "",
        f"Generated from the resolved CycloneDX SBOM by `scripts/render_third_party_notices.py`. Components: {len(components)}.",
        "",
        "Regenerate this file in CI; do not hand-edit dependency rows.",
        "",
        "| Component | Version | Declared licence | Upstream source URL | Package URL (PURL) |",
        "|---|---:|---|---|---|",
    ]
    for component in components:
        name = component.get("name") or "(unnamed component)"
        version = component.get("version") or "unspecified"
        licence = comp_license(component)
        source_url = comp_source_url(component)
        purl = component.get("purl") or "not provided by SBOM metadata"
        if licence.startswith("UNKNOWN") or source_url.startswith("UNKNOWN"):
            unknown.append(f"{name}@{version}: licence={licence}; source URL={source_url}")
        lines.append(
            "| " + " | ".join(cell(v) for v in (name, version, licence, source_url, purl)) + " |"
        )
    lines.extend([
        "",
        f"Metadata completeness: {len(components) - len(unknown)}/{len(components)} components have both a declared licence and an upstream source URL.",
        "",
    ])
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
