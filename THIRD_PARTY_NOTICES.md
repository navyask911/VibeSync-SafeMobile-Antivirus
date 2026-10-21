# Third-party dependency notices

**Generated from the resolved CycloneDX SBOM by CI; do not hand-edit dependency rows.** The generated file must list each resolved direct and transitive dependency with its licence metadata and upstream source URL, plus a package URL (PURL) when the SBOM exposes one.

A package URL is an identifier, not a substitute for an upstream source URL. Components with an unknown licence or missing source URL must remain explicitly listed in the generated **Metadata requiring manual review** section. Unknown metadata is a release blocker until maintainers verify it against the exact published artifact and authoritative upstream source, or remove/replace the component. Do not infer a licence from a project name.

CI renders dependency rows with `scripts/render_third_party_notices.py`. The main-branch SBOM refresh workflow writes the generated full SBOM to `docs/sbom.json` and commits updated output to the repository. The current source branch does not yet contain that materialized resolved-dependency SBOM; its generation/commit remains pending a successful run of the compliance workflow.

- Machine-readable SBOM: [docs/sbom.json](docs/sbom.json), to be generated from the resolved Gradle graph.
- Generator: [scripts/render_third_party_notices.py](scripts/render_third_party_notices.py).
- Dependency and release licence policy: [docs/PROPRIETARY_AND_LICENSE_POLICY.md](docs/PROPRIETARY_AND_LICENSE_POLICY.md).
