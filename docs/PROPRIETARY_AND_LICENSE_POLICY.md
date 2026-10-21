# Proprietary policy, licensing and release boundary

Copyright (c) 2024-2026 Navyask911. The repository root now contains the Apache License 2.0 text for the project source. Project name, icon/artwork and branding remain subject to any separate trademark rights stated in project materials.

Third-party dependencies remain under their own respective licences. The SBOM and third-party notice inventory are generated in CI from the resolved Gradle graph; missing upstream licence/source metadata remains a manual release gate and must not be inferred from the project's root license. Review `docs/sbom.json` and `THIRD_PARTY_NOTICES.md` after the main-branch SBOM refresh workflow has completed.

- Root project licence: [LICENSE](../LICENSE)
- Machine-readable inventory: [SBOM](sbom.json)
- Generated notice renderer: [scripts/render_third_party_notices.py](../scripts/render_third_party_notices.py)
- Runtime coverage boundary: [DETECTION_COVERAGE.md](DETECTION_COVERAGE.md)
- Play restricted permission disclosure: [PLAY_PERMISSIONS.md](PLAY_PERMISSIONS.md)

No root licence grants a right to redistribute bundled malware feeds, YARA rules, training data, model assets, or copied code unless the upstream item is separately verified as compatible and its required attribution/notice is included.
