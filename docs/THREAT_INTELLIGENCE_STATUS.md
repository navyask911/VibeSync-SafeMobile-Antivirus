# Threat-intelligence status and approval gate

## Current verified product state

- Core scanning is local-first and can continue without network connectivity.
- The bundled `offline-threat-definitions.json` contains the harmless EICAR test-marker SHA-256 only. It is not a real-world malware database.
- A generic, user-configured HTTPS JSON/CSV threat-feed importer and indexed local hash/IOC lookups are implemented. No vendor endpoint or credential is configured by default. Requests use HTTPS and may include a user-supplied provider Auth-Key encrypted at rest with Android Keystore; this is transport/provider authentication, not a cryptographically signed feed manifest.
- User-selected JSON imports are schema-validated local inputs, not cryptographically authenticated publisher feeds. The app warns users of this limitation.
- No raw file, file contents, or file hashes are uploaded by the local scanner.
- No VirusTotal Public API integration is permitted in production under this project's policy.

## Candidate sources — not yet authorized for production

MalwareBazaar, URLhaus, ThreatFox, ClamAV signatures, YARA rules, and other community data may be investigated, but they must not be enabled until maintainers confirm the exact current terms, commercial/for-profit access rights, authentication requirements, redistribution permissions, licence notices, provenance, freshness, and false-positive process.

A free-to-download app may still be treated as commercial/for-profit when sponsored or ad-supported. Do not assume an API's no-cost tier permits product use or redistribution.

ClamAV's native engine must not be bundled or linked without prior approval after reviewing its GPL-2 obligations. Community YARA rules require a separate licence review per ruleset; a permissive engine licence does not automatically license every rule collection.

## Required production gates before relying on a remote feed for broad protection

1. Use an approved source with documented redistribution rights.
2. Keep provider credentials out of the Android APK/AAB.
3. Generate normalized, bounded, versioned definitions in a trusted pipeline.
4. Authenticate the published manifest cryptographically; embed only the public verification key.
5. Validate schema, content length, freshness, source metadata, and version before atomic activation.
6. Keep the last-known-valid dataset and local scanning available after failed updates (the custom-feed importer now stages and atomically promotes a successfully parsed response).
7. Add provenance, source date, expiry/freshness state, and test fixtures.
8. Tell users exactly what data is sent by optional lookups; never upload raw user files.
9. Test update signature failure, tampering, rollback, malformed feeds, outages, and empty feeds.
10. Publish no claim of broad malware coverage until a maintained, legally distributable corpus is integrated and measured.

The importer is inactive until the user configures an endpoint. Feed rows are parsed into a disk-backed staging table in bounded batches, then the active indicator index and successful sync state are promoted in one Room transaction only after complete parsing succeeds. Parse, size, authentication, or network failures remove that run's staging rows and preserve the previously active index. This atomicity does not authenticate feed content beyond HTTPS/provider authentication.
