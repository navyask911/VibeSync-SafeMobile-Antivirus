# Production release gate checklist

**Status reviewed:** 22 October 2026  
**Policy:** A CI pass does not imply that every acceptance criterion is met. Do not merge the stack or publish to Play while required gates below are open.

| Gate | Current result | Evidence / owner action |
|---|---|---|
| Offline artifact does not declare INTERNET | CI guard added; current exact-head result pending | Run privacy artifact script against the built `offlineRelease` APK/AAB. Keep `feed` flavor separate. |
| No advertising/analytics/crash SDK markers in release | Dependencies removed; bytecode guard added | Guard checks a list of markers, not every imaginable SDK/package. Review dependency graph/SBOM too. |
| Android backup disabled | Manifest/XML controls present; device behavior unverified | Test each supported Android backup/transfer path on physical devices; do not claim adb backup extraction test passed until measured. |
| Bloom DB / manifest shipped | **Fail** | No production database/assets; loader is not integrated into the ordinary scanner path. |
| YARA runtime / curated rules shipped | **Fail** | No native libyara builds, curated rules, bounded engine, or test artifacts. |
| Trained/evaluated TFLite model shipped | **Fail** | Model asset absent; optional scorer falls back/returns null. |
| Root/hook detection local and unit-tested | **Source + unit tests present; effectiveness not certified** | Tests use injected fake probes; physical rooted-device bypass resistance is not tested. |
| Offline signer pin enforced | **Fail** | Helper exists, but independent expected signer fingerprint is not configured/enforced in ordinary scans. |
| Feed detached signature + rollback | **Source/tests implemented; end-to-end publisher gate open** | Requires public key configuration, a publisher signing service, signed source and runtime proof. No real snapshot is bundled. |
| Feed opt-in off by default | **Source/UI gate present** | Test opt-in on a real device; confirm queue cancellation and no request while switch is off. |
| Room database encrypted or fields minimized | **Partially mitigated; open** | New scan labels, incident labels/paths and quarantine DB labels/paths are AES-SIV field-encrypted with a Keystore-wrapped Tink keyset. Legacy labels may remain plaintext; timestamps, verdicts, session IDs, statuses and other fields remain in the non-SQLCipher Room database. Complete a retention/minimization policy or whole-database encryption review. |
| Quarantine encryption/restore | **Round-trip instrumented test added; exact-head CI and device QA open** | An instrumented test creates an encrypted quarantine copy, restores to a test content provider and compares bytes. Verify tamper detection, Keystore-loss behavior and legacy items on physical devices. |
| Root Apache License 2.0 | Present on branch | Confirm owner intended all included first-party source to be Apache-licensed. Third-party assets/data keep upstream terms. |
| CycloneDX SBOM and third-party notice inventory | **Gradle/CI generation added; materialized artifact pending** | Run SBOM generation, commit/update `docs/sbom.json`, resolve unknown licences/source URLs before release. |
| `QUERY_ALL_PACKAGES` Play declaration | Documentation and disclosure present; **manual review open** | Submit an accurate Play Console Permissions Declaration Form and wait for decision. |
| `MANAGE_EXTERNAL_STORAGE` removed | **Source manifest removed; artifact gate pending** | Verify merged offline manifest; SAF monitor must only access the chosen folder. |
| API 26/30/34/36 emulator matrix | Workflow added; **current exact-head runs pending** | All instrumented matrix jobs must pass on exact final merge head. |
| Large feed and redirect boundary | **Unit tests added; exact-head CI pending** | Streaming tests cover exactly 100 MiB and 100 MiB + 1, relative HTTPS redirects, cross-host auth restrictions and HTTPS downgrade refusal. These are helper-level tests, not full HTTP outage/atomic rollback tests. |
| Debug socket-attempt monitor | **Fail / open** | Add local debug-only instrumentation and prove no scan-time socket attempts; offline manifest check is not a substitute. |
| Native-speaker review | **Fail / open** | Complete `docs/LOCALIZATION_REVIEW.md` for every shipped locale. |
| Version-code monotonicity vs Git tags | Script + CI gate added | Requires full git history. Verify Play Console version usage manually before release. |
| Outage, rollback, permission-denied and SAF-revocation cases | **Incomplete** | Add end-to-end HTTP outage/atomic rollback fixtures, exercise revoked URI grants on devices, and capture device/API evidence. Helper tests alone do not close the full QA gate. |
| Google Play upload | **Manual gate** | Play Console eligibility/version usage/signing/review cannot be inferred from GitHub CI. |

## Release checklist

- [ ] Exact-head CI (unit tests, lint, offline/feed builds, artifact privacy check, all API emulator tests) is green.
- [ ] The final APK/AAB has been inspected, with stored CI logs/artifacts.
- [ ] Production signing key and feed public key were configured through approved secret/variable workflows, and the private feed-signing key remains outside Git.
- [ ] Licensed real signature data plus verified positive/negative detection regression tests are shipped, or product claims remain limited to the actual EICAR baseline.
- [ ] Room privacy and retention decision is implemented and documented.
- [ ] Device backup/extraction, quarantine round-trip, SAF grant/revocation, and feed failure-mode tests are recorded with API/device details.
- [ ] CycloneDX SBOM and notices are generated from the final resolved dependency graph and all unknown licence metadata is resolved or excluded.
- [ ] Play permissions declaration, listing/privacy disclosure, version code, signing and app access are manually verified in Play Console.
- [ ] Native-speaker translation/layout checklist has signed approval.

**No production certification is implied by this checklist or by the word “pass” in any single CI job.**
