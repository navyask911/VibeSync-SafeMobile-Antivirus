# Proprietary software, third-party licence, and change-safety policy

## Current repository facts

- Repository: https://github.com/navyask911/VibeSync-SafeMobile-Antivirus
- Application ID and namespace: `com.vibesync.antivirus`
- The repository is publicly visible on GitHub. Public visibility does not, by itself, transfer copyright, but it does mean source code in the repository is publicly readable. Do not place secrets or private materials here.
- No root `LICENSE` file was present at the baseline commit reviewed for this change. Treat the software's licence status as an unresolved release-governance item until the owner decides whether to add a licence. Do not infer an open-source grant from public visibility.
- This change does not add an Android runtime dependency, native scanner, remote threat-intelligence client, or third-party signature collection.

## Mandatory change rules

1. Preserve package identity, existing architecture, business logic, branding, copyright notices, and signing configuration unless an explicit approval authorizes a change.
2. Make changes on a feature branch, keep diffs reviewable, and do not overwrite unrelated functionality.
3. Before adding a dependency, sample, rule set, database, feed, or code snippet, check its exact source, version, licence, commercial-use restrictions, redistribution conditions, required notices, and transitive dependencies.
4. Do not introduce GPL, AGPL, SSPL, source-available, noncommercial, custom-restricted, or unknown-licence code into the proprietary app without documented approval following a compatibility review. LGPL, MPL, Apache, BSD, MIT, and other licences must be evaluated on their own terms.
5. Do not integrate or link the ClamAV native engine without explicit approval after review of its GPL-2 obligations. Do not integrate the VirusTotal Public API in production. Do not add MalwareBazaar, URLhaus, ThreatFox, or other community feeds for commercial/for-profit usage until current provider terms, redistribution rights, and necessary permissions are confirmed.
6. Do not embed API secrets, signing private keys, keystores, or confidential data in the app or source repository. Keep update-signing keys and provider credentials outside application artifacts.
7. Do not implement an app-spying AccessibilityService, OTP interception, credential capture, silent uninstall, or attempts to evade Android background execution limits.
8. Keep CI permissions restricted, do not expose secrets to untrusted PR code, and review every changed file before merge.
9. Do not claim that licensing, SBOM, copyright, commercial terms, or Google Play eligibility have been fully cleared until evidence supports each claim.

## CI safety guard and dependency inventory

`scripts/check_proprietary_safety.py` checks that the package identity is retained, blocks selected unapproved scanner integrations at the Gradle dependency declaration layer, and detects a small set of common embedded credential formats. It is deliberately narrow and may miss secrets, licence obligations, indirect dependencies, and other risks. It is not a legal review or comprehensive secret scanner.

CI also captures Gradle's `releaseRuntimeClasspath` dependency graph as an artifact so maintainers can review resolved direct and transitive dependencies. That graph is not, by itself, an SBOM or licence report.

## Outstanding before production release

- Generate a complete machine-readable SBOM using an approved, licence-reviewed tool and cover runtime/transitive dependencies.
- Verify the exact licence and required notice for every resolved dependency and each transitive component against the exact published artifact/source.
- Populate `THIRD_PARTY_NOTICES.md` with the actual required notices and licence texts. The file explicitly marks unresolved items rather than pretending the audit is complete.
- Review the repository's licence/ownership posture with the owner; decide whether to add a root licence file or an explicit proprietary-rights notice.
- Obtain legal/terms approval for each threat-intelligence provider and every rule/signature dataset before bundling or redistribution.
- Complete the applicable Google Play policy declarations and permission eligibility review.
